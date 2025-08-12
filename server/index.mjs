import crypto from 'node:crypto';
import os from 'node:os';
import express from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SecureSpotifyConnector } from './secure-credentials.mjs';

class SpotifyClaudeConnector {
  constructor() {
    // Initialiser le gestionnaire de credentials sécurisé
    this.spotifyConnector = new SecureSpotifyConnector();

    // ID utilisateur par défaut (vous pouvez l'adapter selon vos besoins)
    this.defaultUserId = 'claude-user-' + crypto.createHash('md5')
      .update(os.hostname() + os.userInfo().username)
      .digest('hex').substring(0, 8);

    this.server = new Server(
      { name: "secure-spotify-connector", version: "1.0.0" },
      { capabilities: { tools: {} } }
    );

    this.setupOAuthServer();
    this.setupMCPHandlers();

    // Garder une référence globale pour le nettoyage
    global.spotifyConnector = this.spotifyConnector;

    console.log(`🎵 Connecteur Spotify sécurisé initialisé pour l'utilisateur: ${this.defaultUserId}`);
  }

  setupOAuthServer() {
    this.app = express();
    this.app.use(express.json());

    // Route pour le callback OAuth
    this.app.get('/callback', async (req, res) => {
      const { code, state, error } = req.query;

      if (error) {
        res.status(400).send(`❌ Erreur d'authentification: ${error}`);
        return;
      }

      if (!code) {
        res.status(400).send('❌ Code d\'autorisation non fourni');
        return;
      }

      try {
        const tokenData = await this.exchangeCodeForToken(code);

        // Sauvegarder de manière sécurisée
        await this.spotifyConnector.saveTokens(this.defaultUserId, tokenData);

        res.send(`
          <html>
            <head>
              <title>🎵 Authentification Spotify Réussie</title>
              <meta charset="UTF-8">
              <style>
                body { 
                  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                  background: linear-gradient(135deg, #1db954 0%, #191414 100%);
                  color: white;
                  margin: 0;
                  padding: 40px;
                  min-height: 100vh;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                }
                .container {
                  background: rgba(255,255,255,0.1);
                  backdrop-filter: blur(10px);
                  border-radius: 20px;
                  padding: 40px;
                  text-align: center;
                  max-width: 500px;
                  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                }
                .success-icon { font-size: 4em; margin-bottom: 20px; }
                h1 { margin: 20px 0; font-size: 1.8em; }
                p { opacity: 0.9; line-height: 1.6; margin: 20px 0; }
                .info {
                  background: rgba(255,255,255,0.1);
                  padding: 20px;
                  border-radius: 10px;
                  margin: 20px 0;
                  font-size: 0.9em;
                }
                button {
                  background: #1db954;
                  color: white;
                  border: none;
                  padding: 12px 24px;
                  border-radius: 25px;
                  cursor: pointer;
                  font-size: 1em;
                  margin-top: 20px;
                  transition: all 0.3s ease;
                }
                button:hover { 
                  background: #1ed760; 
                  transform: translateY(-2px);
                  box-shadow: 0 4px 12px rgba(29, 185, 84, 0.4);
                }
                .secure-note {
                  font-size: 0.8em;
                  opacity: 0.7;
                  margin-top: 20px;
                }
              </style>
            </head>
            <body>
              <div class="container">
                <div class="success-icon">🎵</div>
                <h1>Authentification Spotify Réussie!</h1>
                <p>Votre connexion Spotify a été configurée avec succès.</p>
                
                <div class="info">
                  <strong>🔐 Sécurité:</strong><br>
                  Vos credentials sont stockés de manière chiffrée localement.<br>
                  <strong>👤 Utilisateur ID:</strong> ${this.defaultUserId}
                </div>
                
                <p>Vous pouvez maintenant:</p>
                <ul style="text-align: left; display: inline-block;">
                  <li>Contrôler votre lecture Spotify</li>
                  <li>Rechercher de la musique</li>
                  <li>Gérer vos playlists</li>
                  <li>Voir votre piste actuelle</li>
                </ul>
                
                <button onclick="window.close()">Fermer cette fenêtre</button>
                
                <div class="secure-note">
                  🛡️ Vos tokens sont chiffrés avec AES-256-GCM
                </div>
              </div>
              
              <script>
                // Auto-fermeture après 10 secondes si pas de clic
                setTimeout(() => {
                  if (!document.hidden) {
                    window.close();
                  }
                }, 10000);
              </script>
            </body>
          </html>
        `);

        console.log(`✅ Authentification réussie et credentials sauvegardés pour: ${this.defaultUserId}`);

      } catch (error) {
        console.error('❌ Erreur OAuth:', error.message);
        res.status(500).send(`
          <html>
            <body style="font-family: Arial, sans-serif; padding: 40px; text-align: center; background: #f44336; color: white;">
              <h2>❌ Erreur d'Authentification</h2>
              <p>Une erreur est survenue: ${error.message}</p>
              <button onclick="window.close()" style="background: white; color: #f44336; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">Fermer</button>
            </body>
          </html>
        `);
      }
    });

    // Route de test de l'état des credentials
    this.app.get('/status', (req, res) => {
      const stats = this.spotifyConnector.credentialsManager.getSecurityStats();
      const hasValidToken = this.spotifyConnector.credentialsManager.isTokenValid(this.defaultUserId);

      res.json({
        user_id: this.defaultUserId,
        has_valid_token: hasValidToken,
        security_stats: stats
      });
    });

    this.app.listen(8080, () => {
      console.log('🔒 Serveur OAuth sécurisé démarré sur http://localhost:8080');
    });
  }

  async exchangeCodeForToken(code) {
    const response = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${Buffer.from(`${this.spotifyConnector.clientId}:${this.spotifyConnector.clientSecret}`).toString('base64')}`
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: this.spotifyConnector.redirectUri
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(`Token exchange failed: ${errorData.error_description || response.statusText}`);
    }

    return await response.json();
  }

  setupMCPHandlers() {
    // Register tools list handler
    this.server.setRequestHandler({
      shape: {
        method: {
          value: 'tools/list',
        }
      }
    }, async () => ({
      tools: [
        {
          name: "spotify_authenticate",
          description: "S'authentifier avec Spotify (OAuth2 sécurisé)",
          inputSchema: {
            type: "object",
            properties: {}
          }
        },
        {
          name: "spotify_status",
          description: "Vérifier le statut de l'authentification",
          inputSchema: {
            type: "object",
            properties: {}
          }
        },
        {
          name: "spotify_get_current_track",
          description: "Obtenir les informations de la piste en cours",
          inputSchema: {
            type: "object",
            properties: {}
          }
        },
        {
          name: "spotify_play_pause",
          description: "Jouer ou mettre en pause",
          inputSchema: {
            type: "object",
            properties: {
              action: {
                type: "string",
                enum: ["play", "pause", "toggle"],
                description: "Action à effectuer"
              }
            }
          }
        },
        {
          name: "spotify_search",
          description: "Rechercher de la musique",
          inputSchema: {
            type: "object",
            properties: {
              query: {
                type: "string",
                description: "Terme de recherche"
              },
              type: {
                type: "string",
                enum: ["track", "artist", "album", "playlist"],
                description: "Type de recherche"
              },
              limit: {
                type: "integer",
                minimum: 1,
                maximum: 50,
                default: 10,
                description: "Nombre de résultats (1-50)"
              }
            },
            required: ["query", "type"]
          }
        },
        {
          name: "spotify_play_track",
          description: "Jouer une piste spécifique",
          inputSchema: {
            type: "object",
            properties: {
              track_uri: {
                type: "string",
                description: "URI Spotify de la piste (spotify:track:...)"
              }
            },
            required: ["track_uri"]
          }
        },
        {
          name: "spotify_next_previous",
          description: "Piste suivante ou précédente",
          inputSchema: {
            type: "object",
            properties: {
              direction: {
                type: "string",
                enum: ["next", "previous"],
                description: "Direction de navigation"
              }
            },
            required: ["direction"]
          }
        },
        {
          name: "spotify_get_playlists",
          description: "Obtenir les playlists de l'utilisateur",
          inputSchema: {
            type: "object",
            properties: {
              limit: {
                type: "integer",
                minimum: 1,
                maximum: 50,
                default: 20,
                description: "Nombre de playlists à récupérer"
              }
            }
          }
        },
        {
          name: "spotify_create_playlist",
          description: "Créer une nouvelle playlist",
          inputSchema: {
            type: "object",
            properties: {
              name: {
                type: "string",
                description: "Nom de la playlist"
              },
              description: {
                type: "string",
                description: "Description de la playlist"
              },
              public: {
                type: "boolean",
                default: false,
                description: "Playlist publique ou privée"
              }
            },
            required: ["name"]
          }
        },
        {
          name: "spotify_security_info",
          description: "Obtenir des informations de sécurité sur les credentials stockés",
          inputSchema: {
            type: "object",
            properties: {}
          }
        },
        {
          name: "spotify_logout",
          description: "Se déconnecter et supprimer les credentials stockés",
          inputSchema: {
            type: "object",
            properties: {}
          }
        }
      ]
    }));

    // Register tools call handler
    this.server.setRequestHandler({
      shape: {
        method: {
          value: 'tools/call',
        }
      }
    }, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'spotify_authenticate':
            return await this.handleAuthentication();
          case 'spotify_status':
            return await this.getAuthStatus();
          case 'spotify_get_current_track':
            return await this.getCurrentTrack();
          case 'spotify_play_pause':
            return await this.handlePlayPause(args.action);
          case 'spotify_search':
            return await this.searchMusic(args.query, args.type, args.limit);
          case 'spotify_play_track':
            return await this.playTrack(args.track_uri);
          case 'spotify_next_previous':
            return await this.navigateTrack(args.direction);
          case 'spotify_get_playlists':
            return await this.getPlaylists(args.limit);
          case 'spotify_create_playlist':
            return await this.createPlaylist(args.name, args.description, args.public);
          case 'spotify_security_info':
            return await this.getSecurityInfo();
          case 'spotify_logout':
            return await this.logout();
          default:
            throw new Error(`Outil inconnu: ${name}`);
        }
      } catch (error) {
        console.error(`❌ Erreur dans ${name}:`, error.message);
        return {
          content: [{
            type: "text",
            text: `❌ **Erreur:** ${error.message}`
          }],
          isError: true
        };
      }
    });
  }

  async handleAuthentication() {
    const state = crypto.randomBytes(16).toString('hex');
    const authUrl = new URL('https://accounts.spotify.com/authorize');

    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', this.spotifyConnector.clientId);
    authUrl.searchParams.set('scope', process.env.SPOTIFY_SCOPES || 'user-read-playback-state user-modify-playback-state user-read-currently-playing playlist-read-private playlist-modify-public playlist-modify-private');
    authUrl.searchParams.set('redirect_uri', this.spotifyConnector.redirectUri);
    authUrl.searchParams.set('state', state);

    return {
      content: [{
        type: "text",
        text: `🎵 **Authentification Spotify Sécurisée**\n\n🔐 Pour vous connecter de manière sécurisée, ouvrez ce lien dans votre navigateur:\n\n${authUrl.toString()}\n\n✨ **Fonctionnalités disponibles après authentification:**\n• Contrôle de lecture (play/pause/next/previous)\n• Recherche de musique avancée\n• Gestion des playlists\n• Informations sur la piste actuelle\n\n🛡️ **Sécurité:** Vos credentials seront chiffrés avec AES-256-GCM et stockés localement de manière sécurisée.\n\n👤 **ID Utilisateur:** \`${this.defaultUserId}\``
      }]
    };
  }

  async getAuthStatus() {
    const hasValidToken = this.spotifyConnector.credentialsManager.isTokenValid(this.defaultUserId);
    const stats = this.spotifyConnector.credentialsManager.getSecurityStats();

    if (hasValidToken) {
      const credentials = this.spotifyConnector.credentialsManager.getCredentials(this.defaultUserId);
      const expiresIn = Math.floor((credentials.expires_at * 1000 - Date.now()) / 1000 / 60);

      return {
        content: [{
          type: "text",
          text: `✅ **Statut: Connecté à Spotify**\n\n🔑 **Token valide:** Oui\n⏰ **Expire dans:** ${expiresIn} minutes\n🎯 **Scopes:** ${credentials.scopes}\n📅 **Dernière mise à jour:** ${credentials.updated_at.toLocaleString()}\n\n📊 **Statistiques de sécurité:**\n• Accès total: ${stats.total_accesses}\n• Dernier accès: ${stats.last_access ? stats.last_access.toLocaleString() : 'N/A'}\n• Credentials stockés: ${stats.stored_credentials}`
        }]
      };
    } else {
      return {
        content: [{
          type: "text",
          text: `❌ **Statut: Non connecté**\n\n🔐 Aucun token valide trouvé.\n\n💡 **Action requise:** Utilisez \`spotify_authenticate\` pour vous connecter.\n\n📊 **Statistiques:**\n• Total accès: ${stats.total_accesses}\n• Credentials stockés: ${stats.stored_credentials}`
        }]
      };
    }
  }

  async getCurrentTrack() {
    const response = await this.spotifyConnector.makeAuthenticatedRequest(
      this.defaultUserId,
      '/me/player/currently-playing'
    );

    if (!response.ok) {
      if (response.status === 204) {
        return {
          content: [{
            type: "text",
            text: "🎵 **Aucune musique en cours de lecture**\n\n💡 Lancez Spotify et commencez à écouter de la musique pour voir les informations ici."
          }]
        };
      }
      throw new Error(`Erreur API Spotify: ${response.statusText}`);
    }

    const data = await response.json();

    if (!data || !data.item) {
      return {
        content: [{
          type: "text",
          text: "🎵 **Aucune piste en cours**\n\n🎧 Spotify est ouvert mais aucune musique n'est en lecture."
        }]
      };
    }

    const track = data.item;
    const artists = track.artists.map(artist => artist.name).join(', ');
    const isPlaying = data.is_playing;
    const progress = data.progress_ms;
    const duration = track.duration_ms;

    const formatTime = (ms) => {
      const minutes = Math.floor(ms / 60000);
      const seconds = Math.floor((ms % 60000) / 1000);
      return `${minutes}:${seconds.toString().padStart(2, '0')}`;
    };

    const progressBar = this.createProgressBar(progress, duration, 20);

    return {
      content: [{
        type: "text",
        text: `🎵 **En cours de lecture:** ${isPlaying ? '▶️' : '⏸️'}\n\n**🎤 Titre:** ${track.name}\n**👨‍🎤 Artiste(s):** ${artists}\n**💿 Album:** ${track.album.name}\n**⏱️ Durée:** ${formatTime(progress)} / ${formatTime(duration)}\n\n${progressBar}\n\n**🔗 URI:** \`${track.uri}\`\n**🌟 Popularité:** ${track.popularity}/100`
      }]
    };
  }

  createProgressBar(current, total, length = 20) {
    const percentage = (current / total) * 100;
    const filled = Math.floor((current / total) * length);
    const empty = length - filled;

    const bar = '█'.repeat(filled) + '░'.repeat(empty);
    return `\`${bar}\` ${Math.floor(percentage)}%`;
  }

  async handlePlayPause(action) {
    let endpoint, method, actionText;

    switch (action) {
      case 'play':
        endpoint = '/me/player/play';
        method = 'PUT';
        actionText = 'Lecture reprise';
        break;
      case 'pause':
        endpoint = '/me/player/pause';
        method = 'PUT';
        actionText = 'Lecture mise en pause';
        break;
      case 'toggle':
        // D'abord récupérer l'état actuel
        const statusResponse = await this.spotifyConnector.makeAuthenticatedRequest(
          this.defaultUserId,
          '/me/player'
        );

        if (statusResponse.ok) {
          const playerState = await statusResponse.json();
          const isPlaying = playerState.is_playing;

          endpoint = isPlaying ? '/me/player/pause' : '/me/player/play';
          method = 'PUT';
          actionText = isPlaying ? 'Lecture mise en pause' : 'Lecture reprise';
        } else {
          throw new Error('Impossible de déterminer l\'état de lecture');
        }
        break;
      default:
        throw new Error(`Action non supportée: ${action}`);
    }

    const response = await this.spotifyConnector.makeAuthenticatedRequest(
      this.defaultUserId,
      endpoint,
      { method }
    );

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Aucun appareil Spotify actif trouvé. Ouvrez Spotify et commencez la lecture.');
      }
      throw new Error(`Erreur de contrôle: ${response.statusText}`);
    }

    return {
      content: [{
        type: "text",
        text: `🎵 **${actionText}** ✅\n\nLa commande a été envoyée à Spotify avec succès.`
      }]
    };
  }

  async searchMusic(query, type, limit = 10) {
    const response = await this.spotifyConnector.makeAuthenticatedRequest(
      this.defaultUserId,
      `/search?q=${encodeURIComponent(query)}&type=${type}&limit=${limit}`
    );

    if (!response.ok) {
      throw new Error(`Erreur de recherche: ${response.statusText}`);
    }

    const data = await response.json();
    const items = data[`${type}s`]?.items || [];

    if (items.length === 0) {
      return {
        content: [{
          type: "text",
          text: `🔍 **Aucun résultat trouvé**\n\nAucun ${type} trouvé pour "${query}"\n\n💡 **Suggestions:**\n• Vérifiez l'orthographe\n• Utilisez des mots-clés plus généraux\n• Essayez un autre type de recherche`
        }]
      };
    }

    let results = `🔍 **Résultats de recherche pour "${query}"** (${type})\n\n`;

    items.forEach((item, index) => {
      if (type === 'track') {
        const artists = item.artists.map(artist => artist.name).join(', ');
        const duration = Math.floor(item.duration_ms / 60000) + ':' +
          String(Math.floor((item.duration_ms % 60000) / 1000)).padStart(2, '0');
        results += `**${index + 1}.** ${item.name}\n`;
        results += `   👨‍🎤 ${artists}\n`;
        results += `   💿 ${item.album.name}\n`;
        results += `   ⏱️ ${duration} • 🌟 ${item.popularity}/100\n`;
        results += `   🔗 \`${item.uri}\`\n\n`;
      } else if (type === 'artist') {
        const followers = item.followers.total.toLocaleString();
        results += `**${index + 1}.** ${item.name}\n`;
        results += `   👥 ${followers} followers\n`;
        results += `   🎵 Genres: ${item.genres.slice(0, 3).join(', ') || 'N/A'}\n`;
        results += `   🌟 ${item.popularity}/100\n`;
        results += `   🔗 \`${item.uri}\`\n\n`;
      } else if (type === 'album') {
        const artists = item.artists.map(artist => artist.name).join(', ');
        results += `**${index + 1}.** ${item.name}\n`;
        results += `   👨‍🎤 ${artists}\n`;
        results += `   📅 ${item.release_date}\n`;
        results += `   🎵 ${item.total_tracks} pistes\n`;
        results += `   🔗 \`${item.uri}\`\n\n`;
      } else if (type === 'playlist') {
        const owner = item.owner.display_name;
        results += `**${index + 1}.** ${item.name}\n`;
        results += `   👤 Par: ${owner}\n`;
        results += `   🎵 ${item.tracks.total} pistes\n`;
        results += `   📝 ${item.description || 'Pas de description'}\n`;
        results += `   🔗 \`${item.uri}\`\n\n`;
      }
    });

    results += `💡 **Astuce:** Utilisez \`spotify_play_track\` avec un URI pour jouer une piste.`;

    return {
      content: [{
        type: "text",
        text: results
      }]
    };
  }

  async playTrack(trackUri) {
    if (!trackUri.startsWith('spotify:track:')) {
      throw new Error('URI invalide. Utilisez un URI Spotify valide (spotify:track:...)');
    }

    const response = await this.spotifyConnector.makeAuthenticatedRequest(
      this.defaultUserId,
      '/me/player/play',
      {
        method: 'PUT',
        body: JSON.stringify({
          uris: [trackUri]
        })
      }
    );

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Aucun appareil Spotify actif. Ouvrez Spotify sur un appareil.');
      }
      throw new Error(`Impossible de jouer la piste: ${response.statusText}`);
    }

    return {
      content: [{
        type: "text",
        text: `🎵 **Lecture démarrée** ✅\n\nLa piste est en cours de lecture sur votre appareil Spotify.\n\n🔗 **URI joué:** \`${trackUri}\``
      }]
    };
  }

  async navigateTrack(direction) {
    const endpoint = direction === 'next' ? '/me/player/next' : '/me/player/previous';

    const response = await this.spotifyConnector.makeAuthenticatedRequest(
      this.defaultUserId,
      endpoint,
      { method: 'POST' }
    );

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Aucun appareil Spotify actif trouvé.');
      }
      throw new Error(`Erreur de navigation: ${response.statusText}`);
    }

    const actionText = direction === 'next' ? 'Piste suivante' : 'Piste précédente';

    return {
      content: [{
        type: "text",
        text: `🎵 **${actionText}** ✅\n\nNavigation effectuée avec succès.`
      }]
    };
  }

  async getPlaylists(limit = 20) {
    const response = await this.spotifyConnector.makeAuthenticatedRequest(
      this.defaultUserId,
      `/me/playlists?limit=${limit}`
    );

    if (!response.ok) {
      throw new Error(`Erreur lors de la récupération des playlists: ${response.statusText}`);
    }

    const data = await response.json();

    if (data.items.length === 0) {
      return {
        content: [{
          type: "text",
          text: "📋 **Aucune playlist trouvée**\n\nVous n'avez pas encore de playlists dans votre compte Spotify."
        }]
      };
    }

    let results = `📋 **Vos Playlists Spotify** (${data.items.length}/${data.total})\n\n`;

    data.items.forEach((playlist, index) => {
      const isOwner = playlist.owner.display_name;
      const isPublic = playlist.public ? '🌍 Public' : '🔒 Privé';

      results += `**${index + 1}.** ${playlist.name}\n`;
      results += `   👤 ${isOwner} • ${isPublic}\n`;
      results += `   🎵 ${playlist.tracks.total} pistes\n`;
      if (playlist.description) {
        results += `   📝 ${playlist.description.substring(0, 100)}${playlist.description.length > 100 ? '...' : ''}\n`;
      }
      results += `   🔗 \`${playlist.uri}\`\n\n`;
    });

    return {
      content: [{
        type: "text",
        text: results
      }]
    };
  }

  async createPlaylist(name, description = '', isPublic = false) {
    // D'abord récupérer l'ID utilisateur
    const userResponse = await this.spotifyConnector.makeAuthenticatedRequest(
      this.defaultUserId,
      '/me'
    );

    if (!userResponse.ok) {
      throw new Error('Impossible de récupérer les informations utilisateur');
    }

    const userData = await userResponse.json();
    const userId = userData.id;

    // Créer la playlist
    const response = await this.spotifyConnector.makeAuthenticatedRequest(
      this.defaultUserId,
      `/users/${userId}/playlists`,
      {
        method: 'POST',
        body: JSON.stringify({
          name: name,
          description: description,
          public: isPublic
        })
      }
    );

    if (!response.ok) {
      throw new Error(`Erreur lors de la création de la playlist: ${response.statusText}`);
    }

    const playlist = await response.json();

    return {
      content: [{
        type: "text",
        text: `📋 **Playlist créée avec succès!** ✅\n\n**🎵 Nom:** ${playlist.name}\n**📝 Description:** ${description || 'Aucune description'}\n**🌍 Visibilité:** ${isPublic ? 'Publique' : 'Privée'}\n**🔗 URI:** \`${playlist.uri}\`\n**🌐 Lien:** ${playlist.external_urls.spotify}\n\n💡 Vous pouvez maintenant ajouter des pistes à cette playlist!`
      }]
    };
  }

  async getSecurityInfo() {
    const stats = this.spotifyConnector.credentialsManager.getSecurityStats();
    const hasValidToken = this.spotifyConnector.credentialsManager.isTokenValid(this.defaultUserId);

    let securityLevel = '🟢 Excellent';
    if (stats.total_accesses > 1000) securityLevel = '🟡 Élevé (beaucoup d\'accès)';
    if (!hasValidToken) securityLevel = '🔴 Non authentifié';

    return {
      content: [{
        type: "text",
        text: `🛡️ **Informations de Sécurité**\n\n**👤 ID Utilisateur:** \`${this.defaultUserId}\`\n**🔑 Token valide:** ${hasValidToken ? '✅ Oui' : '❌ Non'}\n**📊 Niveau de sécurité:** ${securityLevel}\n\n**📈 Statistiques:**\n• Total des accès: ${stats.total_accesses}\n• Credentials stockés: ${stats.stored_credentials}\n• Dernier accès: ${stats.last_access ? stats.last_access.toLocaleString() : 'Jamais'}\n• Empreinte client: \`${stats.client_fingerprint || 'N/A'}\`\n\n**💾 Base de données:**\n• Chemin: \`${stats.database_path}\`\n\n**🔐 Chiffrement:**\n• Algorithm: AES-256-GCM\n• Stockage: Local sécurisé\n• Permissions: Restrictives (0o600)`
      }]
    };
  }

  async logout() {
    const wasLoggedIn = this.spotifyConnector.credentialsManager.isTokenValid(this.defaultUserId);

    if (!wasLoggedIn) {
      return {
        content: [{
          type: "text",
          text: `ℹ️ **Déjà déconnecté**\n\nAucun credential valide trouvé pour l'utilisateur \`${this.defaultUserId}\`.`
        }]
      };
    }

    const success = this.spotifyConnector.credentialsManager.deleteCredentials(this.defaultUserId);

    if (success) {
      return {
        content: [{
          type: "text",
          text: `✅ **Déconnexion réussie**\n\nTous les credentials ont été supprimés de manière sécurisée.\n\n**👤 Utilisateur:** \`${this.defaultUserId}\`\n**🗑️ Action:** Credentials effacés\n**🔒 Sécurité:** Base de données nettoyée\n\n💡 Utilisez \`spotify_authenticate\` pour vous reconnecter.`
        }]
      };
    } else {
      throw new Error('Erreur lors de la suppression des credentials');
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.log('🎵 Connecteur Spotify sécurisé démarré avec succès');
    console.log(`👤 Utilisateur par défaut: ${this.defaultUserId}`);
    console.log(`🔒 Base de données: ${this.spotifyConnector.credentialsManager.dbPath}`);
  }
}

// Démarrer le connecteur
const connector = new SpotifyClaudeConnector();
connector.run().catch(console.error);

// Export pour utilisation externe
export { SpotifyClaudeConnector };

