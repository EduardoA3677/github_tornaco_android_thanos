.class public final Llyiahf/vczjk/j90;
.super Llyiahf/vczjk/x13;
.source "SourceFile"


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/o14;

.field public OooOOOo:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/x13;-><init>(I)V

    new-instance v0, Llyiahf/vczjk/o14;

    invoke-direct {v0, p1}, Llyiahf/vczjk/o14;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/j90;->OooOOOO:Llyiahf/vczjk/o14;

    const/4 p1, -0x1

    iput p1, p0, Llyiahf/vczjk/j90;->OooOOOo:I

    return-void
.end method


# virtual methods
.method public final OooO(I)Llyiahf/vczjk/i90;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/j90;->OooOOOO:Llyiahf/vczjk/o14;

    iget v1, v0, Llyiahf/vczjk/o14;->OooOOOO:I

    if-lt p1, v1, :cond_0

    const/4 v0, -0x1

    goto :goto_0

    :cond_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/o14;->OooO0o(I)I

    move-result v0

    :goto_0
    if-ltz v0, :cond_1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/i90;

    return-object p1

    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-static {p1}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object p1

    const-string v1, "no such label: "

    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0oo()I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/j90;->OooOOOO:Llyiahf/vczjk/o14;

    iget v1, v0, Llyiahf/vczjk/o14;->OooOOOO:I

    add-int/lit8 v1, v1, -0x1

    :goto_0
    if-ltz v1, :cond_0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/o14;->OooO0o(I)I

    move-result v2

    if-gez v2, :cond_0

    add-int/lit8 v1, v1, -0x1

    goto :goto_0

    :cond_0
    add-int/lit8 v1, v1, 0x1

    if-ltz v1, :cond_2

    iget v2, v0, Llyiahf/vczjk/o14;->OooOOOO:I

    if-gt v1, v2, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/wu0;->OooO0Oo()V

    iput v1, v0, Llyiahf/vczjk/o14;->OooOOOO:I

    return v1

    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "newSize > size"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "newSize < 0"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
