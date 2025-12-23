.class public final Llyiahf/vczjk/aw3;
.super Llyiahf/vczjk/e9a;
.source "SourceFile"

# interfaces
.implements Ljava/util/ListIterator;


# instance fields
.field public OooOOO:I

.field public final OooOOO0:I

.field public final OooOOOO:Llyiahf/vczjk/fw3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fw3;I)V
    .locals 1

    invoke-virtual {p1}, Ljava/util/AbstractCollection;->size()I

    move-result v0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p2, v0}, Llyiahf/vczjk/tp6;->OooOOO(II)V

    iput v0, p0, Llyiahf/vczjk/aw3;->OooOOO0:I

    iput p2, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    iput-object p1, p0, Llyiahf/vczjk/aw3;->OooOOOO:Llyiahf/vczjk/fw3;

    return-void
.end method


# virtual methods
.method public final OooO00o(I)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/aw3;->OooOOOO:Llyiahf/vczjk/fw3;

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final add(Ljava/lang/Object;)V
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final hasNext()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    iget v1, p0, Llyiahf/vczjk/aw3;->OooOOO0:I

    if-ge v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final hasPrevious()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    if-lez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/aw3;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    add-int/lit8 v1, v0, 0x1

    iput v1, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    invoke-virtual {p0, v0}, Llyiahf/vczjk/aw3;->OooO00o(I)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :cond_0
    new-instance v0, Ljava/util/NoSuchElementException;

    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    throw v0
.end method

.method public final nextIndex()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    return v0
.end method

.method public final previous()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/aw3;->hasPrevious()Z

    move-result v0

    if-eqz v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    invoke-virtual {p0, v0}, Llyiahf/vczjk/aw3;->OooO00o(I)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :cond_0
    new-instance v0, Ljava/util/NoSuchElementException;

    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    throw v0
.end method

.method public final previousIndex()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/aw3;->OooOOO:I

    add-int/lit8 v0, v0, -0x1

    return v0
.end method

.method public final set(Ljava/lang/Object;)V
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method
