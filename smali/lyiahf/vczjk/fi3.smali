.class public final Llyiahf/vczjk/fi3;
.super Llyiahf/vczjk/ky4;
.source "SourceFile"


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/fi3;

.field public static final OooO0OO:Llyiahf/vczjk/ei3;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/fi3;

    invoke-direct {v0}, Llyiahf/vczjk/ky4;-><init>()V

    sput-object v0, Llyiahf/vczjk/fi3;->OooO0O0:Llyiahf/vczjk/fi3;

    new-instance v0, Llyiahf/vczjk/ei3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/fi3;->OooO0OO:Llyiahf/vczjk/ei3;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ty4;)V
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/u22;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/u22;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "owner"

    sget-object v1, Llyiahf/vczjk/fi3;->OooO0OO:Llyiahf/vczjk/ei3;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1, v1}, Llyiahf/vczjk/u22;->onStart(Llyiahf/vczjk/uy4;)V

    invoke-interface {p1, v1}, Llyiahf/vczjk/u22;->OooO0oO(Llyiahf/vczjk/uy4;)V

    return-void

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " must implement androidx.lifecycle.DefaultLifecycleObserver."

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/jy4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/jy4;->OooOOo0:Llyiahf/vczjk/jy4;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/ty4;)V
    .locals 0

    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "coil.request.GlobalLifecycle"

    return-object v0
.end method
