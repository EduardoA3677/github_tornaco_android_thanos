.class public final Llyiahf/vczjk/h8a;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/h8a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/h8a;

    invoke-direct {v0}, Llyiahf/vczjk/qr1;-><init>()V

    sput-object v0, Llyiahf/vczjk/h8a;->OooOOOO:Llyiahf/vczjk/h8a;

    return-void
.end method


# virtual methods
.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 0

    sget-object p2, Llyiahf/vczjk/sta;->OooOOOO:Llyiahf/vczjk/up3;

    invoke-interface {p1, p2}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sta;

    if-eqz p1, :cond_0

    const/4 p2, 0x1

    iput-boolean p2, p1, Llyiahf/vczjk/sta;->OooOOO:Z

    return-void

    :cond_0
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Dispatchers.Unconfined.dispatch function can only be used by the yield function. If you wrap Unconfined dispatcher in your code, make sure you properly delegate isDispatchNeeded and dispatch calls."

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final o00000oo(I)Llyiahf/vczjk/qr1;
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "limitedParallelism is not supported for Dispatchers.Unconfined"

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "Dispatchers.Unconfined"

    return-object v0
.end method
