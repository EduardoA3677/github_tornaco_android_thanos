.class public final Llyiahf/vczjk/pb6;
.super Llyiahf/vczjk/gy;
.source "SourceFile"


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:Llyiahf/vczjk/qo;


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/qo;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/pb6;->OooOOO0:Llyiahf/vczjk/qo;

    iput p1, p0, Llyiahf/vczjk/pb6;->OooOOO:I

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0O0(ILlyiahf/vczjk/qo;)V
    .locals 0

    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1}, Ljava/lang/IllegalStateException;-><init>()V

    throw p1
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pb6;->OooOOO:I

    if-ne p1, v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/pb6;->OooOOO0:Llyiahf/vczjk/qo;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ob6;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/ob6;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method
