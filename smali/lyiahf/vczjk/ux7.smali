.class public final Llyiahf/vczjk/ux7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/tx7;

.field public static OooO0OO:Ljava/util/Map;

.field public static OooO0Oo:Ljava/util/Map;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/sw7;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/tx7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/ux7;->OooO0O0:Llyiahf/vczjk/tx7;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/sw7;)V
    .locals 4

    const-string v0, "ruleDao"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ux7;->OooO00o:Llyiahf/vczjk/sw7;

    sget-object p1, Llyiahf/vczjk/ii3;->OooOOO0:Llyiahf/vczjk/ii3;

    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v1, Llyiahf/vczjk/sx7;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/sx7;-><init>(Llyiahf/vczjk/ux7;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x2

    invoke-static {p1, v0, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
