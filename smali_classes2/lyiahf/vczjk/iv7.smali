.class public final Llyiahf/vczjk/iv7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public OooOOO:Llyiahf/vczjk/cm0;

.field public final OooOOO0:Llyiahf/vczjk/hv7;

.field public OooOOOO:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jv7;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/hv7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/hv7;-><init>(Llyiahf/vczjk/im0;)V

    iput-object v0, p0, Llyiahf/vczjk/iv7;->OooOOO0:Llyiahf/vczjk/hv7;

    invoke-virtual {v0}, Llyiahf/vczjk/hv7;->OooO00o()Llyiahf/vczjk/h25;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/cm0;

    invoke-direct {v1, v0}, Llyiahf/vczjk/cm0;-><init>(Llyiahf/vczjk/h25;)V

    iput-object v1, p0, Llyiahf/vczjk/iv7;->OooOOO:Llyiahf/vczjk/cm0;

    iget p1, p1, Llyiahf/vczjk/jv7;->OooOOO:I

    iput p1, p0, Llyiahf/vczjk/iv7;->OooOOOO:I

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/iv7;->OooOOOO:I

    if-lez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/iv7;->OooOOO:Llyiahf/vczjk/cm0;

    invoke-virtual {v0}, Llyiahf/vczjk/cm0;->hasNext()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/iv7;->OooOOO0:Llyiahf/vczjk/hv7;

    invoke-virtual {v0}, Llyiahf/vczjk/hv7;->OooO00o()Llyiahf/vczjk/h25;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/cm0;

    invoke-direct {v1, v0}, Llyiahf/vczjk/cm0;-><init>(Llyiahf/vczjk/h25;)V

    iput-object v1, p0, Llyiahf/vczjk/iv7;->OooOOO:Llyiahf/vczjk/cm0;

    :cond_0
    iget v0, p0, Llyiahf/vczjk/iv7;->OooOOOO:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p0, Llyiahf/vczjk/iv7;->OooOOOO:I

    iget-object v0, p0, Llyiahf/vczjk/iv7;->OooOOO:Llyiahf/vczjk/cm0;

    invoke-virtual {v0}, Llyiahf/vczjk/cm0;->nextByte()B

    move-result v0

    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object v0

    return-object v0
.end method

.method public final remove()V
    .locals 1

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw v0
.end method
