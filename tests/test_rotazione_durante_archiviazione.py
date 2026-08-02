"""
Corsa fra l'archiviazione e la rotazione dei log di Wazuh.

Caso reale (Domarc, tre notti consecutive dal 2026-07-31): il ciclo parte alle
00:01, elenca i file da includere trovando `ossec-alerts-01.log`, impiega 65
secondi a costruire l'archivio, e nel frattempo Wazuh comprime quel file in
`ossec-alerts-01.log.gz`. Il risultato era
`[Errno 2] No such file or directory` e l'abbandono dell'INTERO archivio da
434 MB per un solo file in transito.
"""
import tarfile
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from archiver import Archiver, ArchiveError, LogFile          # noqa: E402
from models import ArchiveConfig, CompressionType, ArchiveInterval  # noqa: E402


def _archiver(tmp: Path) -> Archiver:
    cfg = ArchiveConfig(
        compression=CompressionType.GZIP,
        compression_level=1,
        naming_pattern="wazuh-logs-{date}-{hour}.tar.gz",
        temp_dir=tmp,
        interval=ArchiveInterval.DAILY,
    )
    return Archiver(cfg)


def _logfile(p: Path) -> LogFile:
    return LogFile(path=p, size=p.stat().st_size, modified_time=datetime.now())


def _nomi_nel_tar(archivio: Path):
    with tarfile.open(archivio, "r:*") as t:
        return {Path(n).name for n in t.getnames()}


class TestRotazioneDuranteArchiviazione(unittest.TestCase):
    def test_il_file_ruotato_viene_incluso_come_compresso(self):
        """Il caso osservato sul campo: il .log sparisce, il .log.gz compare."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            buono = root / "ossec-alerts-02.json"
            buono.write_text("evento rimasto\n")
            ruotato = root / "ossec-alerts-01.log"
            ruotato.write_text("evento del giorno chiuso\n")

            files = [_logfile(buono), _logfile(ruotato)]

            # la rotazione avviene DOPO l'elenco: il .log diventa .log.gz
            compresso = root / "ossec-alerts-01.log.gz"
            compresso.write_bytes(b"contenuto compresso")
            ruotato.unlink()

            arch = _archiver(root)
            record = arch.create_archive(files, datetime(2026, 8, 1))

            self.assertTrue(record.archive_path.exists())
            nomi = _nomi_nel_tar(record.archive_path)
            self.assertIn("ossec-alerts-01.log.gz", nomi,
                          "il file ruotato doveva essere incluso nella sua forma compressa")
            self.assertIn("ossec-alerts-02.json", nomi,
                          "gli altri file non devono essere persi")

    def test_un_file_sparito_senza_compresso_non_butta_via_l_archivio(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            buono = root / "ossec-alerts-02.json"
            buono.write_text("evento rimasto\n")
            sparito = root / "ossec-alerts-01.log"
            sparito.write_text("sto per sparire\n")

            files = [_logfile(buono), _logfile(sparito)]
            sparito.unlink()  # nessun .gz al suo posto

            arch = _archiver(root)
            record = arch.create_archive(files, datetime(2026, 8, 1))

            nomi = _nomi_nel_tar(record.archive_path)
            self.assertIn("ossec-alerts-02.json", nomi)
            self.assertNotIn("ossec-alerts-01.log", nomi)

    def test_il_manifest_interno_dichiara_sostituiti_e_mancanti(self):
        """Un'esclusione silenziosa sarebbe peggio del fallimento: deve restare traccia."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            buono = root / "ossec-alerts-02.json"
            buono.write_text("evento rimasto\n")
            ruotato = root / "ossec-alerts-01.log"
            ruotato.write_text("x\n")
            perso = root / "ossec-archive-01.log"
            perso.write_text("y\n")

            files = [_logfile(buono), _logfile(ruotato), _logfile(perso)]
            (root / "ossec-alerts-01.log.gz").write_bytes(b"compresso")
            ruotato.unlink()
            perso.unlink()

            arch = _archiver(root)
            record = arch.create_archive(files, datetime(2026, 8, 1))

            import json
            with tarfile.open(record.archive_path, "r:*") as t:
                manifest = json.loads(t.extractfile("manifest.json").read().decode())
            self.assertIn("rotated_during_archiving", manifest)
            self.assertTrue(any("ossec-alerts-01.log" in s for s in manifest["rotated_during_archiving"]))
            self.assertIn("missing_at_archiving", manifest)
            self.assertTrue(any("ossec-archive-01.log" in s for s in manifest["missing_at_archiving"]))

    def test_se_spariscono_tutti_l_archivio_non_viene_prodotto(self):
        """Un archivio vuoto che passa per riuscito sarebbe una falsa rassicurazione."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "ossec-alerts-01.log"; a.write_text("x\n")
            b = root / "ossec-alerts-02.log"; b.write_text("y\n")
            files = [_logfile(a), _logfile(b)]
            a.unlink(); b.unlink()

            arch = _archiver(root)
            with self.assertRaises(ArchiveError):
                arch.create_archive(files, datetime(2026, 8, 1))

    def test_nessuna_rotazione_nulla_cambia(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "ossec-alerts-01.log"; a.write_text("uno\n")
            b = root / "ossec-alerts-02.json"; b.write_text("due\n")
            arch = _archiver(root)
            record = arch.create_archive([_logfile(a), _logfile(b)], datetime(2026, 8, 1))
            nomi = _nomi_nel_tar(record.archive_path)
            self.assertIn("ossec-alerts-01.log", nomi)
            self.assertIn("ossec-alerts-02.json", nomi)


    def test_il_record_non_dichiara_i_file_esclusi(self):
        """Il record e' materiale probatorio: dichiarare un file escluso come
        archiviato e' peggio del fallimento che questa modifica evita."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            buono = root / "ossec-alerts-02.json"; buono.write_text("rimasto\n")
            ruotato = root / "ossec-alerts-01.log"; ruotato.write_text("x\n")
            perso = root / "ossec-archive-01.log"; perso.write_text("y\n")
            files = [_logfile(buono), _logfile(ruotato), _logfile(perso)]
            compresso = root / "ossec-alerts-01.log.gz"
            compresso.write_bytes(b"compresso")
            ruotato.unlink(); perso.unlink()

            arch = _archiver(root)
            record = arch.create_archive(files, datetime(2026, 8, 1))

            self.assertNotIn(str(perso), record.source_files,
                             "un file escluso non deve comparire fra le sorgenti dichiarate")
            self.assertIn(str(compresso), record.source_files,
                          "il sostituto compresso deve comparire, non l'originale sparito")
            self.assertNotIn(str(ruotato), record.source_files)
            self.assertIn(str(buono), record.source_files)

    def test_gli_oggetti_del_chiamante_non_vengono_alterati(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ruotato = root / "ossec-alerts-01.log"; ruotato.write_text("x\n")
            lf = _logfile(ruotato)
            dimensione_prima, percorso_prima = lf.size, lf.path
            (root / "ossec-alerts-01.log.gz").write_bytes(b"compresso piu lungo del semplice")
            ruotato.unlink()

            _archiver(root).create_archive([lf], datetime(2026, 8, 1))

            self.assertEqual(lf.path, percorso_prima, "il path del chiamante e' stato mutato")
            self.assertEqual(lf.size, dimensione_prima, "la dimensione del chiamante e' stata mutata")

    @unittest.skipIf(hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0,
                     "da root i permessi non bloccano la lettura")
    def test_un_errore_diverso_da_file_mancante_fa_fallire_il_ciclo(self):
        """Permessi negati sul sostituto non devono essere riclassificati come
        'file in transito' ed esclusi in silenzio.

        Nel batch DEVE esserci anche un file valido: con un solo file il ciclo
        fallirebbe comunque per l'interruzione preesistente "nessun file
        archiviabile", e il test passerebbe anche col difetto reintrodotto.
        """
        import os
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            buono = root / "ossec-alerts-02.json"; buono.write_text("questo si legge\n")
            ruotato = root / "ossec-alerts-01.log"; ruotato.write_text("x\n")
            files = [_logfile(buono), _logfile(ruotato)]
            compresso = root / "ossec-alerts-01.log.gz"
            compresso.write_bytes(b"compresso")
            ruotato.unlink()
            os.chmod(compresso, 0o000)
            try:
                with self.assertRaises(ArchiveError):
                    _archiver(root).create_archive(files, datetime(2026, 8, 1))
            finally:
                os.chmod(compresso, 0o644)


if __name__ == "__main__":
    unittest.main()
