.class public final Llyiahf/vczjk/ge6;
.super Llyiahf/vczjk/jp8;
.source "SourceFile"


# instance fields
.field public OooOo:[I

.field public OooOo0O:[Llyiahf/vczjk/b23;

.field public OooOo0o:I

.field public OooOoO:[Ljava/lang/Object;

.field public OooOoO0:I

.field public OooOoOO:I


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 v0, 0x10

    new-array v1, v0, [Llyiahf/vczjk/b23;

    iput-object v1, p0, Llyiahf/vczjk/ge6;->OooOo0O:[Llyiahf/vczjk/b23;

    new-array v1, v0, [I

    iput-object v1, p0, Llyiahf/vczjk/ge6;->OooOo:[I

    new-array v0, v0, [Ljava/lang/Object;

    iput-object v0, p0, Llyiahf/vczjk/ge6;->OooOoO:[Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooooOO()V
    .locals 4

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/ge6;->OooOo0o:I

    iput v0, p0, Llyiahf/vczjk/ge6;->OooOoO0:I

    iget-object v1, p0, Llyiahf/vczjk/ge6;->OooOoO:[Ljava/lang/Object;

    iget v2, p0, Llyiahf/vczjk/ge6;->OooOoOO:I

    const/4 v3, 0x0

    invoke-static {v1, v0, v2, v3}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    iput v0, p0, Llyiahf/vczjk/ge6;->OooOoOO:I

    return-void
.end method

.method public final OooooOo(Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/ge6;->Oooooo()Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance v0, Llyiahf/vczjk/j11;

    invoke-direct {v0, p0}, Llyiahf/vczjk/j11;-><init>(Llyiahf/vczjk/ge6;)V

    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/j11;->OooO0o0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ge6;

    iget-object v2, v1, Llyiahf/vczjk/ge6;->OooOo0O:[Llyiahf/vczjk/b23;

    iget v3, v0, Llyiahf/vczjk/j11;->OooO0O0:I

    aget-object v2, v2, v3

    invoke-virtual {v2, v0, p1, p2, p3}, Llyiahf/vczjk/b23;->OooO0OO(Llyiahf/vczjk/j11;Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V

    iget v2, v0, Llyiahf/vczjk/j11;->OooO0O0:I

    iget v3, v1, Llyiahf/vczjk/ge6;->OooOo0o:I

    if-lt v2, v3, :cond_0

    goto :goto_1

    :cond_0
    iget-object v1, v1, Llyiahf/vczjk/ge6;->OooOo0O:[Llyiahf/vczjk/b23;

    aget-object v1, v1, v2

    iget v4, v0, Llyiahf/vczjk/j11;->OooO0OO:I

    iget v5, v1, Llyiahf/vczjk/b23;->OooO0O0:I

    add-int/2addr v4, v5

    iput v4, v0, Llyiahf/vczjk/j11;->OooO0OO:I

    iget v4, v0, Llyiahf/vczjk/j11;->OooO0Oo:I

    iget v1, v1, Llyiahf/vczjk/b23;->OooO0OO:I

    add-int/2addr v4, v1

    iput v4, v0, Llyiahf/vczjk/j11;->OooO0Oo:I

    add-int/lit8 v2, v2, 0x1

    iput v2, v0, Llyiahf/vczjk/j11;->OooO0O0:I

    if-ge v2, v3, :cond_1

    goto :goto_0

    :cond_1
    :goto_1
    invoke-virtual {p0}, Llyiahf/vczjk/ge6;->OooooOO()V

    return-void
.end method

.method public final Oooooo()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ge6;->OooOo0o:I

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooooo0()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ge6;->OooOo0o:I

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooooO(Llyiahf/vczjk/b23;)V
    .locals 6

    iget v0, p0, Llyiahf/vczjk/ge6;->OooOo0o:I

    iget-object v1, p0, Llyiahf/vczjk/ge6;->OooOo0O:[Llyiahf/vczjk/b23;

    array-length v2, v1

    const/16 v3, 0x400

    const/4 v4, 0x0

    if-ne v0, v2, :cond_1

    if-le v0, v3, :cond_0

    move v2, v3

    goto :goto_0

    :cond_0
    move v2, v0

    :goto_0
    add-int/2addr v2, v0

    new-array v2, v2, [Llyiahf/vczjk/b23;

    invoke-static {v1, v4, v2, v4, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    iput-object v2, p0, Llyiahf/vczjk/ge6;->OooOo0O:[Llyiahf/vczjk/b23;

    :cond_1
    iget v0, p0, Llyiahf/vczjk/ge6;->OooOoO0:I

    iget v1, p1, Llyiahf/vczjk/b23;->OooO0O0:I

    add-int/2addr v0, v1

    iget-object v1, p0, Llyiahf/vczjk/ge6;->OooOo:[I

    array-length v2, v1

    if-le v0, v2, :cond_4

    if-le v2, v3, :cond_2

    move v5, v3

    goto :goto_1

    :cond_2
    move v5, v2

    :goto_1
    add-int/2addr v5, v2

    if-ge v5, v0, :cond_3

    goto :goto_2

    :cond_3
    move v0, v5

    :goto_2
    new-array v0, v0, [I

    invoke-static {v4, v4, v2, v1, v0}, Llyiahf/vczjk/sy;->ooOO(III[I[I)V

    iput-object v0, p0, Llyiahf/vczjk/ge6;->OooOo:[I

    :cond_4
    iget v0, p0, Llyiahf/vczjk/ge6;->OooOoOO:I

    iget v1, p1, Llyiahf/vczjk/b23;->OooO0OO:I

    add-int/2addr v0, v1

    iget-object v2, p0, Llyiahf/vczjk/ge6;->OooOoO:[Ljava/lang/Object;

    array-length v5, v2

    if-le v0, v5, :cond_7

    if-le v5, v3, :cond_5

    goto :goto_3

    :cond_5
    move v3, v5

    :goto_3
    add-int/2addr v3, v5

    if-ge v3, v0, :cond_6

    goto :goto_4

    :cond_6
    move v0, v3

    :goto_4
    new-array v0, v0, [Ljava/lang/Object;

    invoke-static {v2, v4, v0, v4, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    iput-object v0, p0, Llyiahf/vczjk/ge6;->OooOoO:[Ljava/lang/Object;

    :cond_7
    iget-object v0, p0, Llyiahf/vczjk/ge6;->OooOo0O:[Llyiahf/vczjk/b23;

    iget v2, p0, Llyiahf/vczjk/ge6;->OooOo0o:I

    add-int/lit8 v3, v2, 0x1

    iput v3, p0, Llyiahf/vczjk/ge6;->OooOo0o:I

    aput-object p1, v0, v2

    iget v0, p0, Llyiahf/vczjk/ge6;->OooOoO0:I

    iget p1, p1, Llyiahf/vczjk/b23;->OooO0O0:I

    add-int/2addr v0, p1

    iput v0, p0, Llyiahf/vczjk/ge6;->OooOoO0:I

    iget p1, p0, Llyiahf/vczjk/ge6;->OooOoOO:I

    add-int/2addr p1, v1

    iput p1, p0, Llyiahf/vczjk/ge6;->OooOoOO:I

    return-void
.end method
