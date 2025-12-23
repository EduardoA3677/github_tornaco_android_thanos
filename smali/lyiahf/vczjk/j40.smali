.class public abstract Llyiahf/vczjk/j40;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/mw;

.field public static final OooO0O0:Llyiahf/vczjk/mw;

.field public static final OooO0OO:Llyiahf/vczjk/mw;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/mw;

    new-instance v1, Llyiahf/vczjk/ow;

    const/4 v2, 0x4

    invoke-direct {v1, v2}, Llyiahf/vczjk/ow;-><init>(I)V

    const-string v2, "filterEnableStateEnabled"

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/mw;-><init>(Ljava/lang/String;Llyiahf/vczjk/oe3;)V

    sput-object v0, Llyiahf/vczjk/j40;->OooO00o:Llyiahf/vczjk/mw;

    new-instance v0, Llyiahf/vczjk/mw;

    new-instance v1, Llyiahf/vczjk/ow;

    const/4 v2, 0x5

    invoke-direct {v1, v2}, Llyiahf/vczjk/ow;-><init>(I)V

    const-string v2, "filterEnableStateDisabled"

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/mw;-><init>(Ljava/lang/String;Llyiahf/vczjk/oe3;)V

    sput-object v0, Llyiahf/vczjk/j40;->OooO0O0:Llyiahf/vczjk/mw;

    new-instance v0, Llyiahf/vczjk/mw;

    new-instance v1, Llyiahf/vczjk/ow;

    const/4 v2, 0x6

    invoke-direct {v1, v2}, Llyiahf/vczjk/ow;-><init>(I)V

    const-string v2, "filterEnableStateAll"

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/mw;-><init>(Ljava/lang/String;Llyiahf/vczjk/oe3;)V

    sput-object v0, Llyiahf/vczjk/j40;->OooO0OO:Llyiahf/vczjk/mw;

    return-void
.end method
