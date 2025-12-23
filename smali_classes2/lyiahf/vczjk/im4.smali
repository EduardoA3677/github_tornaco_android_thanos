.class public final Llyiahf/vczjk/im4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/zl1;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/im4;

.field public static final OooO0O0:Llyiahf/vczjk/zg9;

.field public static final OooO0OO:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/im4;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    new-instance v0, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v1, "StateHolder"

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/vl6;->OooO0O0()Llyiahf/vczjk/u99;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v1, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object v1, v1, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    invoke-static {v0, v1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/cm4;

    const/4 v2, 0x1

    const-string v3, "PREMIUM"

    invoke-direct {v1, v3, v2, v2}, Llyiahf/vczjk/cm4;-><init>(Ljava/lang/String;ZZ)V

    new-instance v2, Llyiahf/vczjk/oi7;

    invoke-direct {v2}, Llyiahf/vczjk/oi7;-><init>()V

    new-instance v3, Llyiahf/vczjk/ai7;

    invoke-direct {v3, v1, v0, v2}, Llyiahf/vczjk/ai7;-><init>(Llyiahf/vczjk/cm4;Llyiahf/vczjk/to1;Llyiahf/vczjk/oi7;)V

    new-instance v0, Llyiahf/vczjk/zg9;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v3, v0, Llyiahf/vczjk/zg9;->OooO00o:Ljava/lang/Object;

    sput-object v0, Llyiahf/vczjk/im4;->OooO0O0:Llyiahf/vczjk/zg9;

    const/16 v0, 0x8

    sput v0, Llyiahf/vczjk/im4;->OooO0OO:I

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/dm4;

    const/4 v1, 0x2

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/dn8;->o0OoOo0(Llyiahf/vczjk/im4;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/v74;

    return-void
.end method
