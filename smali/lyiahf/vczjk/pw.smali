.class public abstract Llyiahf/vczjk/pw;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/mw;

.field public static final OooO0O0:Llyiahf/vczjk/mw;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/mw;

    new-instance v1, Llyiahf/vczjk/ow;

    const/4 v2, 0x0

    invoke-direct {v1, v2}, Llyiahf/vczjk/ow;-><init>(I)V

    const-string v2, "System"

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/mw;-><init>(Ljava/lang/String;Llyiahf/vczjk/oe3;)V

    sput-object v0, Llyiahf/vczjk/pw;->OooO00o:Llyiahf/vczjk/mw;

    new-instance v0, Llyiahf/vczjk/mw;

    new-instance v1, Llyiahf/vczjk/ow;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Llyiahf/vczjk/ow;-><init>(I)V

    const-string v2, "User"

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/mw;-><init>(Ljava/lang/String;Llyiahf/vczjk/oe3;)V

    sput-object v0, Llyiahf/vczjk/pw;->OooO0O0:Llyiahf/vczjk/mw;

    return-void
.end method
