.class public final Llyiahf/vczjk/bs1;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/bs1;

.field public static final OooOOOo:Llyiahf/vczjk/q32;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/bs1;

    invoke-direct {v0}, Llyiahf/vczjk/qr1;-><init>()V

    sput-object v0, Llyiahf/vczjk/bs1;->OooOOOO:Llyiahf/vczjk/bs1;

    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sput-object v0, Llyiahf/vczjk/bs1;->OooOOOo:Llyiahf/vczjk/q32;

    return-void
.end method


# virtual methods
.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "block"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/bs1;->OooOOOo:Llyiahf/vczjk/q32;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/k88;->o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final o00000oO(Llyiahf/vczjk/or1;)Z
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/bs1;->OooOOOo:Llyiahf/vczjk/q32;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    xor-int/lit8 p1, p1, 0x1

    return p1
.end method
