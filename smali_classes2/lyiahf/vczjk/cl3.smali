.class public final enum Llyiahf/vczjk/cl3;
.super Llyiahf/vczjk/sl3;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "Sh"

    const/16 v1, 0xb

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/content/Context;Llyiahf/vczjk/fo9;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Llyiahf/vczjk/ej8;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    sget-object p2, Llyiahf/vczjk/he0;->OooO00o:Llyiahf/vczjk/fo9;

    const/4 p2, 0x0

    invoke-static {p2}, Lcom/topjohnwu/superuser/fallback/Shell$Config;->verboseLogging(Z)V

    return-object p1
.end method
