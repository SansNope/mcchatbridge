package com.example.mcchatbridge;

import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.common.Mod;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.ServerChatEvent;
import net.neoforged.neoforge.event.entity.living.LivingDeathEvent;
import net.neoforged.neoforge.event.entity.player.PlayerEvent;
import net.neoforged.neoforge.event.server.ServerStartingEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;

@Mod("mcchatbridge")
public class McChatBridge {
    public static MinecraftServer server;

    public McChatBridge(IEventBus modEventBus) {
        NeoForge.EVENT_BUS.register(this);
    }

    @SubscribeEvent
    public void onServerStarting(ServerStartingEvent event) {
        server = event.getServer();
        HttpWebServer.start(8080);
    }

    @SubscribeEvent
    public void onServerStopping(ServerStoppingEvent event) {
        HttpWebServer.stop();
        server = null;
    }

    @SubscribeEvent
    public void onChat(ServerChatEvent event) {
        if (event.getPlayer() != null) {
            String name = event.getPlayer().getGameProfile().getName();
            String message = event.getMessage().getString();
            HttpWebServer.broadcastToWeb(name, message, false);
        }
    }

    @SubscribeEvent
    public void onPlayerJoin(PlayerEvent.PlayerLoggedInEvent event) {
        if (event.getEntity() != null) {
            String name = event.getEntity().getGameProfile().getName();
            HttpWebServer.broadcastToWeb("[Server]", "§e" + name + " joined the game", false);
        }
    }

    @SubscribeEvent
    public void onPlayerLeave(PlayerEvent.PlayerLoggedOutEvent event) {
        if (event.getEntity() != null) {
            String name = event.getEntity().getGameProfile().getName();
            HttpWebServer.broadcastToWeb("[Server]", "§e" + name + " left the game", false);
        }
    }

    @SubscribeEvent
    public void onPlayerDeath(LivingDeathEvent event) {
        if (event.getEntity() instanceof ServerPlayer) {
            ServerPlayer player = (ServerPlayer) event.getEntity();
            String deathMessage = player.getCombatTracker().getDeathMessage().getString();
            HttpWebServer.broadcastToWeb("[Server]", "§c" + deathMessage, false);
        }
    }

    public static void sendToMinecraft(String nick, String message, String host) {
        if (server != null) {
            Component component;
            if (message.contains("[img]") && message.contains("[/img]")) {
                String imgPath = message.substring(message.indexOf("[img]") + 5, message.indexOf("[/img]"));
                String fullUrl = "http://" + host + imgPath;
                component = Component.literal("§7[Web] §f<" + nick + "> ")
                        .append(Component.literal("§b[[CICode,url=" + fullUrl + ",name=Изображение]]")
                                .withStyle(style -> style
                                        .withClickEvent(new net.minecraft.network.chat.ClickEvent(net.minecraft.network.chat.ClickEvent.Action.OPEN_URL, fullUrl))
                                        .withHoverEvent(new net.minecraft.network.chat.HoverEvent(net.minecraft.network.chat.HoverEvent.Action.SHOW_TEXT, Component.literal("Открыть изображение в браузере")))
                                )
                        );
            } else {
                String formatted = "§7[Web] §f<" + nick + "> " + message;
                component = Component.literal(formatted);
            }
            server.getPlayerList().broadcastSystemMessage(component, false);
        }
    }

    public static void sendToMinecraft(String nick, String message) {
        sendToMinecraft(nick, message, "localhost:8080");
    }

    public static void sendPrivateToMinecraft(String from, String to, String message) {
        if (server != null) {
            ServerPlayer player = server.getPlayerList().getPlayerByName(to);
            if (player != null) {
                player.sendSystemMessage(Component.literal("§d[Web PM] " + from + " -> вам: " + message));
            }
        }
    }

    public static String getServerMotd() {
        if (server != null) {
            return server.getMotd();
        }
        return "A Minecraft Server";
    }

    public static int getOnlineCount() {
        return server != null ? server.getPlayerCount() : 0;
    }

    public static int getMaxPlayers() {
        return server != null ? server.getMaxPlayers() : 20;
    }

    public static String getOnlinePlayersJson() {
        return HttpWebServer.getOnlinePlayersJson();
    }
}
