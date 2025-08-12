import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';

class SecureCredentialsManager {
  constructor() {
    this.dbPath = this.getSecureDbPath();
    this.encryptionKey = this.getOrCreateEncryptionKey();
    this.db = this.initializeDatabase();
  }

  /**
   * Obtient le chemin sécurisé pour la base de données
   * Utilise le répertoire utilisateur approprié selon l'OS
   */
  getSecureDbPath() {
    const appDataDir = process.platform === 'win32'
      ? path.join(os.homedir(), 'AppData', 'Local', 'SpotifyClaudeConnector')
      : process.platform === 'darwin'
        ? path.join(os.homedir(), 'Library', 'Application Support', 'SpotifyClaudeConnector')
        : path.join(os.homedir(), '.config', 'spotify-claude-connector');

    // Créer le répertoire s'il n'existe pas
    if (!fs.existsSync(appDataDir)) {
      fs.mkdirSync(appDataDir, { recursive: true, mode: 0o700 }); // Permissions restrictives
    }

    return path.join(appDataDir, 'credentials.db');
  }

  /**
   * Génère ou récupère la clé de chiffrement
   * Stockée dans le keychain système ou un fichier sécurisé
   */
  getOrCreateEncryptionKey() {
    const keyPath = path.join(path.dirname(this.dbPath), '.encryption.key');

    try {
      if (fs.existsSync(keyPath)) {
        return fs.readFileSync(keyPath);
      }
    } catch (error) {
      console.warn('⚠️ Impossible de lire la clé existante, génération d\'une nouvelle clé');
    }

    // Générer une nouvelle clé de 32 bytes
    const key = crypto.randomBytes(32);

    try {
      // Sauvegarder avec permissions restrictives
      fs.writeFileSync(keyPath, key, { mode: 0o600 });
      console.log('🔐 Nouvelle clé de chiffrement générée');
    } catch (error) {
      console.error('❌ Erreur lors de la sauvegarde de la clé:', error.message);
      throw new Error('Impossible de sauvegarder la clé de chiffrement');
    }

    return key;
  }

  /**
   * Initialise la base de données SQLite avec les tables nécessaires
   */
  initializeDatabase() {
    const db = new DatabaseSync(this.dbPath);

    // Configurer SQLite pour la sécurité
    db.exec('PRAGMA journal_mode = WAL');
    db.exec('PRAGMA synchronous = FULL');
    db.exec('PRAGMA foreign_keys = ON');
    db.exec('PRAGMA secure_delete = ON');

    // Créer la table des credentials
    db.exec(`
      CREATE TABLE IF NOT EXISTS spotify_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        encrypted_access_token TEXT NOT NULL,
        encrypted_refresh_token TEXT NOT NULL,
        token_type TEXT NOT NULL DEFAULT 'Bearer',
        expires_at INTEGER NOT NULL,
        scopes TEXT NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (unixepoch()),
        updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
        iv_access TEXT NOT NULL,
        iv_refresh TEXT NOT NULL,
        auth_tag_access TEXT NOT NULL,
        auth_tag_refresh TEXT NOT NULL
      )
    `);

    // Créer la table des métadonnées de sécurité
    db.exec(`
      CREATE TABLE IF NOT EXISTS security_metadata (
        id INTEGER PRIMARY KEY,
        last_access INTEGER NOT NULL DEFAULT (unixepoch()),
        access_count INTEGER NOT NULL DEFAULT 0,
        client_fingerprint TEXT,
        created_at INTEGER NOT NULL DEFAULT (unixepoch())
      )
    `);

    // Créer un trigger pour mettre à jour updated_at
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS update_credentials_timestamp 
      AFTER UPDATE ON spotify_credentials
      BEGIN
        UPDATE spotify_credentials 
        SET updated_at = unixepoch()
        WHERE id = NEW.id;
      END
    `);

    // Créer des index pour les performances
    db.exec('CREATE INDEX IF NOT EXISTS idx_user_id ON spotify_credentials(user_id)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_expires_at ON spotify_credentials(expires_at)');

    console.log(`✅ Base de données initialisée: ${this.dbPath}`);
    return db;
  }

  /**
   * Chiffre une valeur avec AES-256-GCM
   */
  encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-gcm', this.encryptionKey);
    cipher.setAAD(Buffer.from('spotify-credentials', 'utf8'));

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
      encrypted: encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  /**
   * Déchiffre une valeur avec AES-256-GCM
   */
  decrypt(encryptedData, iv, authTag) {
    const decipher = crypto.createDecipher('aes-256-gcm', this.encryptionKey);
    decipher.setAAD(Buffer.from('spotify-credentials', 'utf8'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Sauvegarde les tokens Spotify de manière chiffrée
   */
  saveCredentials(userId, tokenData) {
    try {
      const { access_token, refresh_token, expires_in, token_type = 'Bearer', scope } = tokenData;

      // Chiffrer les tokens
      const encryptedAccess = this.encrypt(access_token);
      const encryptedRefresh = this.encrypt(refresh_token);

      // Calculer l'expiration
      const expiresAt = Math.floor(Date.now() / 1000) + (expires_in || 3600);

      // Préparer la requête avec node:sqlite
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO spotify_credentials 
        (user_id, encrypted_access_token, encrypted_refresh_token, token_type, 
         expires_at, scopes, iv_access, iv_refresh, auth_tag_access, auth_tag_refresh) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = stmt.run(
        userId,
        encryptedAccess.encrypted,
        encryptedRefresh.encrypted,
        token_type,
        expiresAt,
        scope || '',
        encryptedAccess.iv,
        encryptedRefresh.iv,
        encryptedAccess.authTag,
        encryptedRefresh.authTag
      );

      this.updateSecurityMetadata();

      console.log(`✅ Credentials sauvegardés pour l'utilisateur: ${userId}`);
      return result.lastInsertRowid;

    } catch (error) {
      console.error('❌ Erreur lors de la sauvegarde des credentials:', error.message);
      throw new Error('Impossible de sauvegarder les credentials');
    }
  }

  /**
   * Récupère et déchiffre les credentials
   */
  getCredentials(userId) {
    try {
      const stmt = this.db.prepare(`
        SELECT * FROM spotify_credentials
        WHERE user_id = ?
        ORDER BY updated_at DESC
        LIMIT 1
      `);

      const row = stmt.get(userId);

      if (!row) {
        return null;
      }

      // Vérifier si le token a expiré
      const now = Math.floor(Date.now() / 1000);
      const isExpired = now >= row.expires_at;

      // Déchiffrer les tokens
      const accessToken = this.decrypt(
        row.encrypted_access_token,
        row.iv_access,
        row.auth_tag_access
      );

      const refreshToken = this.decrypt(
        row.encrypted_refresh_token,
        row.iv_refresh,
        row.auth_tag_refresh
      );

      this.updateSecurityMetadata();

      return {
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: row.token_type,
        expires_at: row.expires_at,
        scopes: row.scopes,
        is_expired: isExpired,
        created_at: new Date(row.created_at * 1000),
        updated_at: new Date(row.updated_at * 1000)
      };

    } catch (error) {
      console.error('❌ Erreur lors de la récupération des credentials:', error.message);
      return null;
    }
  }

  /**
   * Met à jour les métadonnées de sécurité
   */
  updateSecurityMetadata() {
    try {
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO security_metadata 
        (id, last_access, access_count, client_fingerprint) 
        VALUES (
          1, 
          unixepoch(),
          COALESCE((SELECT access_count FROM security_metadata WHERE id = 1), 0) + 1,
          ?
        )
      `);

      const fingerprint = this.generateClientFingerprint();
      stmt.run(fingerprint);

    } catch (error) {
      console.warn('⚠️ Impossible de mettre à jour les métadonnées de sécurité:', error.message);
    }
  }

  /**
   * Génère une empreinte du client pour détecter les accès suspects
   */
  generateClientFingerprint() {
    const data = `${os.hostname()}-${os.platform()}-${os.arch()}-${process.version}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  /**
   * Vérifie si les credentials sont valides et non expirés
   */
  isTokenValid(userId) {
    const credentials = this.getCredentials(userId);
    if (!credentials) return false;

    const now = Math.floor(Date.now() / 1000);
    return now < credentials.expires_at;
  }

  /**
   * Supprime les credentials d'un utilisateur
   */
  deleteCredentials(userId) {
    try {
      const stmt = this.db.prepare('DELETE FROM spotify_credentials WHERE user_id = ?');
      const result = stmt.run(userId);

      console.log(`🗑️ Credentials supprimés pour l'utilisateur: ${userId}`);
      return result.changes > 0;

    } catch (error) {
      console.error('❌ Erreur lors de la suppression:', error.message);
      return false;
    }
  }

  /**
   * Nettoie les credentials expirés (tâche de maintenance)
   */
  cleanupExpiredCredentials() {
    try {
      const stmt = this.db.prepare(`
        DELETE FROM spotify_credentials 
        WHERE expires_at < unixepoch()
        AND updated_at < unixepoch() - 604800
      `);

      const result = stmt.run();
      console.log(`🧹 ${result.changes} credentials expirés supprimés`);

      return result.changes;
    } catch (error) {
      console.error('❌ Erreur lors du nettoyage:', error.message);
      return 0;
    }
  }

  /**
   * Obtient des statistiques de sécurité
   */
  getSecurityStats() {
    try {
      const credentialsCount = this.db.prepare('SELECT COUNT(*) as count FROM spotify_credentials').get().count;
      const metadata = this.db.prepare('SELECT * FROM security_metadata WHERE id = 1').get();

      return {
        stored_credentials: credentialsCount,
        last_access: metadata ? new Date(metadata.last_access * 1000) : null,
        total_accesses: metadata ? metadata.access_count : 0,
        client_fingerprint: metadata ? metadata.client_fingerprint : null,
        database_path: this.dbPath,
        database_size: this.getDatabaseSize()
      };
    } catch (error) {
      console.error('❌ Erreur lors de la récupération des stats:', error.message);
      return null;
    }
  }

  /**
   * Obtient la taille de la base de données
   */
  getDatabaseSize() {
    try {
      const stats = fs.statSync(this.dbPath);
      return {
        bytes: stats.size,
        human: this.formatBytes(stats.size)
      };
    } catch (error) {
      return { bytes: 0, human: '0 B' };
    }
  }

  /**
   * Formate les bytes en format lisible
   */
  formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  /**
   * Ferme la connexion à la base de données
   */
  close() {
    if (this.db) {
      this.db.close();
      console.log('🔒 Connexion à la base de données fermée');
    }
  }

  /**
   * Sauvegarde la base de données (avec node:sqlite, on utilise une copie de fichier)
   */
  backup(backupPath) {
    try {
      // Avec node:sqlite, on doit faire une copie manuelle du fichier
      fs.copyFileSync(this.dbPath, backupPath);
      console.log(`💾 Sauvegarde créée: ${backupPath}`);
      return true;
    } catch (error) {
      console.error('❌ Erreur lors de la sauvegarde:', error.message);
      return false;
    }
  }

  /**
   * Optimise la base de données
   */
  optimize() {
    try {
      this.db.exec('VACUUM');
      this.db.exec('ANALYZE');
      console.log('✅ Base de données optimisée');
      return true;
    } catch (error) {
      console.error('❌ Erreur lors de l\'optimisation:', error.message);
      return false;
    }
  }

  /**
   * Vérifie l'intégrité de la base de données
   */
  checkIntegrity() {
    try {
      const result = this.db.prepare('PRAGMA integrity_check').get();
      const isOk = result.integrity_check === 'ok';

      if (isOk) {
        console.log('✅ Intégrité de la base de données: OK');
      } else {
        console.warn('⚠️ Problème d\'intégrité détecté:', result.integrity_check);
      }

      return isOk;
    } catch (error) {
      console.error('❌ Erreur lors de la vérification d\'intégrité:', error.message);
      return false;
    }
  }
}

// Exemple d'utilisation intégrée dans le connecteur Spotify
class SecureSpotifyConnector {
  constructor() {
    this.credentialsManager = new SecureCredentialsManager();
    this.clientId = process.env.SPOTIFY_CLIENT_ID;
    this.clientSecret = process.env.SPOTIFY_CLIENT_SECRET;
    this.redirectUri = process.env.SPOTIFY_REDIRECT_URI || 'http://localhost:8080/callback';

    // Nettoyage automatique au démarrage
    this.credentialsManager.cleanupExpiredCredentials();

    // Vérification d'intégrité périodique
    setInterval(() => {
      this.credentialsManager.checkIntegrity();
    }, 24 * 60 * 60 * 1000); // 24 heures
  }

  async saveTokens(userId, tokenData) {
    return this.credentialsManager.saveCredentials(userId, tokenData);
  }

  async getValidToken(userId) {
    const credentials = this.credentialsManager.getCredentials(userId);

    if (!credentials) {
      throw new Error('Aucun credential trouvé. Authentification requise.');
    }

    if (credentials.is_expired) {
      console.log('🔄 Token expiré, tentative de refresh...');
      return await this.refreshToken(userId, credentials.refresh_token);
    }

    return credentials;
  }

  async refreshToken(userId, refreshToken) {
    try {
      const response = await fetch('https://accounts.spotify.com/api/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken
        })
      });

      if (!response.ok) {
        throw new Error(`Token refresh failed: ${response.statusText}`);
      }

      const newTokens = await response.json();

      // Sauvegarder les nouveaux tokens
      await this.saveTokens(userId, {
        ...newTokens,
        refresh_token: refreshToken // Conserver le refresh token s'il n'est pas renouvelé
      });

      console.log('✅ Token rafraîchi avec succès');
      return this.credentialsManager.getCredentials(userId);

    } catch (error) {
      console.error('❌ Erreur lors du refresh du token:', error.message);
      throw error;
    }
  }

  async makeAuthenticatedRequest(userId, endpoint, options = {}) {
    const credentials = await this.getValidToken(userId);

    const response = await fetch(`https://api.spotify.com/v1${endpoint}`, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `${credentials.token_type} ${credentials.access_token}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.status === 401) {
      // Token invalide, tenter un refresh
      await this.refreshToken(userId, credentials.refresh_token);

      // Retry avec le nouveau token
      const newCredentials = await this.getValidToken(userId);
      return fetch(`https://api.spotify.com/v1${endpoint}`, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `${newCredentials.token_type} ${newCredentials.access_token}`,
          'Content-Type': 'application/json'
        }
      });
    }

    return response;
  }

  // Nettoyage en cas d'arrêt propre
  cleanup() {
    this.credentialsManager.close();
  }
}

export {
  SecureCredentialsManager,
  SecureSpotifyConnector
};

// Gestion propre de l'arrêt
process.on('SIGINT', () => {
  console.log('\n🛑 Arrêt du connecteur...');
  if (global.spotifyConnector) {
    global.spotifyConnector.cleanup();
  }
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Arrêt demandé...');
  if (global.spotifyConnector) {
    global.spotifyConnector.cleanup();
  }
  process.exit(0);
});