.class public final Llyiahf/vczjk/tj6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Ljava/util/LinkedHashMap;

.field public final OooO00o:Llyiahf/vczjk/o55;

.field public final OooO0O0:Ljava/util/ArrayList;

.field public final OooO0OO:Ljava/util/ArrayList;

.field public OooO0Oo:I

.field public OooO0o:I

.field public OooO0o0:I

.field public final OooO0oO:Llyiahf/vczjk/jj0;

.field public final OooO0oo:Llyiahf/vczjk/jj0;

.field public final OooOO0:Llyiahf/vczjk/ed5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o55;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tj6;->OooO00o:Llyiahf/vczjk/o55;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tj6;->OooO0O0:Ljava/util/ArrayList;

    iput-object p1, p0, Llyiahf/vczjk/tj6;->OooO0OO:Ljava/util/ArrayList;

    const/4 p1, -0x1

    const/4 v0, 0x0

    const/4 v1, 0x6

    invoke-static {p1, v1, v0}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/tj6;->OooO0oO:Llyiahf/vczjk/jj0;

    invoke-static {p1, v1, v0}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tj6;->OooO0oo:Llyiahf/vczjk/jj0;

    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tj6;->OooO:Ljava/util/LinkedHashMap;

    new-instance p1, Llyiahf/vczjk/ed5;

    const/4 v0, 0x4

    invoke-direct {p1, v0}, Llyiahf/vczjk/ed5;-><init>(I)V

    sget-object v0, Llyiahf/vczjk/s25;->OooOOO0:Llyiahf/vczjk/s25;

    sget-object v1, Llyiahf/vczjk/o25;->OooO0O0:Llyiahf/vczjk/o25;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/ed5;->Oooo0oO(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)V

    iput-object p1, p0, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/mja;)Llyiahf/vczjk/rn6;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/tj6;->OooO0OO:Ljava/util/ArrayList;

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/tj6;->OooO00o:Llyiahf/vczjk/o55;

    if-eqz p1, :cond_3

    iget v3, p0, Llyiahf/vczjk/tj6;->OooO0o0:I

    iget v4, p0, Llyiahf/vczjk/tj6;->OooO0Oo:I

    neg-int v4, v4

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v5

    iget v6, p0, Llyiahf/vczjk/tj6;->OooO0Oo:I

    sub-int/2addr v5, v6

    move v6, v4

    :goto_0
    iget v7, p1, Llyiahf/vczjk/mja;->OooO0o0:I

    if-ge v6, v7, :cond_1

    if-le v6, v5, :cond_0

    const/16 v7, 0x14

    goto :goto_1

    :cond_0
    iget v7, p0, Llyiahf/vczjk/tj6;->OooO0Oo:I

    add-int/2addr v7, v6

    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/pn6;

    iget-object v7, v7, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    invoke-interface {v7}, Ljava/util/List;->size()I

    move-result v7

    :goto_1
    add-int/2addr v3, v7

    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_1
    iget p1, p1, Llyiahf/vczjk/mja;->OooO0o:I

    add-int/2addr v3, p1

    if-ge v7, v4, :cond_2

    add-int/lit8 v3, v3, -0x14

    :cond_2
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    goto :goto_2

    :cond_3
    const/4 p1, 0x0

    :goto_2
    iget v0, p0, Llyiahf/vczjk/tj6;->OooO0o0:I

    new-instance v3, Llyiahf/vczjk/rn6;

    invoke-direct {v3, v1, p1, v2, v0}, Llyiahf/vczjk/rn6;-><init>(Ljava/util/List;Ljava/lang/Integer;Llyiahf/vczjk/o55;I)V

    return-object v3
.end method

.method public final OooO0O0(ILlyiahf/vczjk/s25;Llyiahf/vczjk/pn6;)Z
    .locals 9

    const-string v0, "loadType"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "page"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/tj6;->OooO0O0:Ljava/util/ArrayList;

    iget-object v1, p0, Llyiahf/vczjk/tj6;->OooO0OO:Ljava/util/ArrayList;

    const/high16 v2, -0x80000000

    const/4 v3, 0x0

    const/4 v4, 0x1

    iget v5, p3, Llyiahf/vczjk/pn6;->OooOOOO:I

    iget v6, p3, Llyiahf/vczjk/pn6;->OooOOOo:I

    if-eqz p2, :cond_c

    iget-object v7, p0, Llyiahf/vczjk/tj6;->OooO:Ljava/util/LinkedHashMap;

    iget-object v8, p3, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    if-eq p2, v4, :cond_6

    const/4 v5, 0x2

    if-eq p2, v5, :cond_0

    return v4

    :cond_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p2

    if-nez p2, :cond_5

    if-eqz p1, :cond_1

    goto :goto_2

    :cond_1
    invoke-virtual {v0, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    if-ne v6, v2, :cond_3

    iget p1, p0, Llyiahf/vczjk/tj6;->OooO0o:I

    invoke-interface {v8}, Ljava/util/List;->size()I

    move-result p2

    sub-int/2addr p1, p2

    if-gez p1, :cond_2

    move v6, v3

    goto :goto_0

    :cond_2
    move v6, p1

    :cond_3
    :goto_0
    if-ne v6, v2, :cond_4

    goto :goto_1

    :cond_4
    move v3, v6

    :goto_1
    iput v3, p0, Llyiahf/vczjk/tj6;->OooO0o:I

    sget-object p1, Llyiahf/vczjk/s25;->OooOOOO:Llyiahf/vczjk/s25;

    invoke-interface {v7, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return v4

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "should\'ve received an init before append"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_6
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p2

    if-nez p2, :cond_b

    if-eqz p1, :cond_7

    :goto_2
    return v3

    :cond_7
    invoke-virtual {v0, v3, p3}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    iget p1, p0, Llyiahf/vczjk/tj6;->OooO0Oo:I

    add-int/2addr p1, v4

    iput p1, p0, Llyiahf/vczjk/tj6;->OooO0Oo:I

    if-ne v5, v2, :cond_9

    iget p1, p0, Llyiahf/vczjk/tj6;->OooO0o0:I

    invoke-interface {v8}, Ljava/util/List;->size()I

    move-result p2

    sub-int/2addr p1, p2

    if-gez p1, :cond_8

    move v5, v3

    goto :goto_3

    :cond_8
    move v5, p1

    :cond_9
    :goto_3
    if-ne v5, v2, :cond_a

    goto :goto_4

    :cond_a
    move v3, v5

    :goto_4
    iput v3, p0, Llyiahf/vczjk/tj6;->OooO0o0:I

    sget-object p1, Llyiahf/vczjk/s25;->OooOOO:Llyiahf/vczjk/s25;

    invoke-interface {v7, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return v4

    :cond_b
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "should\'ve received an init before prepend"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_c
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p2

    if-eqz p2, :cond_10

    if-nez p1, :cond_f

    invoke-virtual {v0, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iput v3, p0, Llyiahf/vczjk/tj6;->OooO0Oo:I

    if-ne v6, v2, :cond_d

    move v6, v3

    :cond_d
    iput v6, p0, Llyiahf/vczjk/tj6;->OooO0o:I

    if-ne v5, v2, :cond_e

    goto :goto_5

    :cond_e
    move v3, v5

    :goto_5
    iput v3, p0, Llyiahf/vczjk/tj6;->OooO0o0:I

    return v4

    :cond_f
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "init loadId must be the initial value, 0"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_10
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "cannot receive multiple init calls"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/pn6;Llyiahf/vczjk/s25;)Llyiahf/vczjk/ii6;
    .locals 11

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v0, :cond_2

    if-eq v0, v3, :cond_1

    if-ne v0, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tj6;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/tj6;->OooO0Oo:I

    sub-int/2addr v0, v1

    add-int/lit8 v1, v0, -0x1

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    iget v0, p0, Llyiahf/vczjk/tj6;->OooO0Oo:I

    sub-int/2addr v1, v0

    :cond_2
    :goto_0
    new-instance v0, Llyiahf/vczjk/fy9;

    iget-object p1, p1, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/fy9;-><init>(ILjava/util/List;)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v6

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    if-eqz p1, :cond_5

    const/4 v10, 0x0

    if-eq p1, v3, :cond_4

    if-ne p1, v2, :cond_3

    sget-object p1, Llyiahf/vczjk/ii6;->OooO0oO:Llyiahf/vczjk/ii6;

    iget v8, p0, Llyiahf/vczjk/tj6;->OooO0o:I

    invoke-virtual {p2}, Llyiahf/vczjk/ed5;->Oooo0oo()Llyiahf/vczjk/r25;

    move-result-object v9

    new-instance v4, Llyiahf/vczjk/ii6;

    sget-object v5, Llyiahf/vczjk/s25;->OooOOOO:Llyiahf/vczjk/s25;

    const/4 v7, -0x1

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/ii6;-><init>(Llyiahf/vczjk/s25;Ljava/util/List;IILlyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V

    return-object v4

    :cond_3
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_4
    sget-object p1, Llyiahf/vczjk/ii6;->OooO0oO:Llyiahf/vczjk/ii6;

    iget v7, p0, Llyiahf/vczjk/tj6;->OooO0o0:I

    invoke-virtual {p2}, Llyiahf/vczjk/ed5;->Oooo0oo()Llyiahf/vczjk/r25;

    move-result-object v9

    new-instance v4, Llyiahf/vczjk/ii6;

    sget-object v5, Llyiahf/vczjk/s25;->OooOOO:Llyiahf/vczjk/s25;

    const/4 v8, -0x1

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/ii6;-><init>(Llyiahf/vczjk/s25;Ljava/util/List;IILlyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V

    return-object v4

    :cond_5
    sget-object p1, Llyiahf/vczjk/ii6;->OooO0oO:Llyiahf/vczjk/ii6;

    iget v7, p0, Llyiahf/vczjk/tj6;->OooO0o0:I

    iget v8, p0, Llyiahf/vczjk/tj6;->OooO0o:I

    invoke-virtual {p2}, Llyiahf/vczjk/ed5;->Oooo0oo()Llyiahf/vczjk/r25;

    move-result-object v9

    new-instance v4, Llyiahf/vczjk/ii6;

    sget-object v5, Llyiahf/vczjk/s25;->OooOOO0:Llyiahf/vczjk/s25;

    const/4 v10, 0x0

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/ii6;-><init>(Llyiahf/vczjk/s25;Ljava/util/List;IILlyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V

    return-object v4
.end method
