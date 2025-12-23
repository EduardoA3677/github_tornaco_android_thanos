.class public abstract Llyiahf/vczjk/uu5;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/a0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/sw7;

    const/16 v1, 0x13

    invoke-direct {v0, v1}, Llyiahf/vczjk/sw7;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/rt3;

    const/16 v2, 0x12

    invoke-direct {v1, v2}, Llyiahf/vczjk/rt3;-><init>(I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v3, Llyiahf/vczjk/tu5;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v2

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/sw7;->OooO0o0(Llyiahf/vczjk/gf4;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v0}, Llyiahf/vczjk/sw7;->OooO0o()Llyiahf/vczjk/a0;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/uu5;->OooO00o:Llyiahf/vczjk/a0;

    return-void
.end method
