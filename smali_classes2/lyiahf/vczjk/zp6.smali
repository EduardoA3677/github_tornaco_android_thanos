.class public final Llyiahf/vczjk/zp6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Comparable;


# static fields
.field public static final OooOOO:Ljava/lang/String;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/jm0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Ljava/io/File;->separator:Ljava/lang/String;

    const-string v1, "separator"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/zp6;->OooOOO:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/jm0;)V
    .locals 1

    const-string v0, "bytes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/util/ArrayList;
    .locals 8

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-static {p0}, Llyiahf/vczjk/OooOO0;->OooO00o(Llyiahf/vczjk/zp6;)I

    move-result v1

    const/4 v2, -0x1

    const/16 v3, 0x5c

    iget-object v4, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    if-ne v1, v2, :cond_0

    const/4 v1, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {v4}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v2

    if-ge v1, v2, :cond_1

    invoke-virtual {v4, v1}, Llyiahf/vczjk/jm0;->OooOO0O(I)B

    move-result v2

    if-ne v2, v3, :cond_1

    add-int/lit8 v1, v1, 0x1

    :cond_1
    :goto_0
    invoke-virtual {v4}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v2

    move v5, v1

    :goto_1
    if-ge v1, v2, :cond_4

    invoke-virtual {v4, v1}, Llyiahf/vczjk/jm0;->OooOO0O(I)B

    move-result v6

    const/16 v7, 0x2f

    if-eq v6, v7, :cond_2

    invoke-virtual {v4, v1}, Llyiahf/vczjk/jm0;->OooOO0O(I)B

    move-result v6

    if-ne v6, v3, :cond_3

    :cond_2
    invoke-virtual {v4, v5, v1}, Llyiahf/vczjk/jm0;->OooOOOo(II)Llyiahf/vczjk/jm0;

    move-result-object v5

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v5, v1, 0x1

    :cond_3
    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_4
    invoke-virtual {v4}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v1

    if-ge v5, v1, :cond_5

    invoke-virtual {v4}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v1

    invoke-virtual {v4, v5, v1}, Llyiahf/vczjk/jm0;->OooOOOo(II)Llyiahf/vczjk/jm0;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_5
    return-object v0
.end method

.method public final OooO0O0()Ljava/lang/String;
    .locals 4

    sget-object v0, Llyiahf/vczjk/OooOO0;->OooO00o:Llyiahf/vczjk/jm0;

    sget-object v0, Llyiahf/vczjk/OooOO0;->OooO00o:Llyiahf/vczjk/jm0;

    iget-object v1, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-static {v1, v0}, Llyiahf/vczjk/jm0;->OooOOO0(Llyiahf/vczjk/jm0;Llyiahf/vczjk/jm0;)I

    move-result v0

    const/4 v2, -0x1

    if-eq v0, v2, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/OooOO0;->OooO0O0:Llyiahf/vczjk/jm0;

    invoke-static {v1, v0}, Llyiahf/vczjk/jm0;->OooOOO0(Llyiahf/vczjk/jm0;Llyiahf/vczjk/jm0;)I

    move-result v0

    :goto_0
    const/4 v3, 0x2

    if-eq v0, v2, :cond_1

    add-int/lit8 v0, v0, 0x1

    const/4 v2, 0x0

    invoke-static {v1, v0, v2, v3}, Llyiahf/vczjk/jm0;->OooOOo0(Llyiahf/vczjk/jm0;III)Llyiahf/vczjk/jm0;

    move-result-object v1

    goto :goto_1

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/zp6;->OooO0oo()Ljava/lang/Character;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v0

    if-ne v0, v3, :cond_2

    sget-object v1, Llyiahf/vczjk/jm0;->OooOOOO:Llyiahf/vczjk/jm0;

    :cond_2
    :goto_1
    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooOOoo()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/zp6;
    .locals 10

    sget-object v0, Llyiahf/vczjk/OooOO0;->OooO0Oo:Llyiahf/vczjk/jm0;

    iget-object v1, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_b

    sget-object v2, Llyiahf/vczjk/OooOO0;->OooO00o:Llyiahf/vczjk/jm0;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_b

    sget-object v3, Llyiahf/vczjk/OooOO0;->OooO0O0:Llyiahf/vczjk/jm0;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_b

    sget-object v4, Llyiahf/vczjk/OooOO0;->OooO0o0:Llyiahf/vczjk/jm0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v5, "suffix"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v5

    invoke-virtual {v4}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v6

    sub-int/2addr v5, v6

    invoke-virtual {v4}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v6

    invoke-virtual {v1, v5, v4, v6}, Llyiahf/vczjk/jm0;->OooOOOO(ILlyiahf/vczjk/jm0;I)Z

    move-result v4

    const/4 v5, 0x3

    const/4 v6, 0x2

    const/4 v7, 0x1

    if-eqz v4, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v4

    if-ne v4, v6, :cond_0

    goto/16 :goto_1

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v4

    sub-int/2addr v4, v5

    invoke-virtual {v1, v4, v2, v7}, Llyiahf/vczjk/jm0;->OooOOOO(ILlyiahf/vczjk/jm0;I)Z

    move-result v4

    if-eqz v4, :cond_1

    goto/16 :goto_1

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v4

    sub-int/2addr v4, v5

    invoke-virtual {v1, v4, v3, v7}, Llyiahf/vczjk/jm0;->OooOOOO(ILlyiahf/vczjk/jm0;I)Z

    move-result v4

    if-eqz v4, :cond_2

    goto/16 :goto_1

    :cond_2
    invoke-static {v1, v2}, Llyiahf/vczjk/jm0;->OooOOO0(Llyiahf/vczjk/jm0;Llyiahf/vczjk/jm0;)I

    move-result v2

    const/4 v4, -0x1

    if-eq v2, v4, :cond_3

    goto :goto_0

    :cond_3
    invoke-static {v1, v3}, Llyiahf/vczjk/jm0;->OooOOO0(Llyiahf/vczjk/jm0;Llyiahf/vczjk/jm0;)I

    move-result v2

    :goto_0
    const/4 v8, 0x0

    if-ne v2, v6, :cond_5

    invoke-virtual {p0}, Llyiahf/vczjk/zp6;->OooO0oo()Ljava/lang/Character;

    move-result-object v9

    if-eqz v9, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v0

    if-ne v0, v5, :cond_4

    goto :goto_1

    :cond_4
    new-instance v0, Llyiahf/vczjk/zp6;

    invoke-static {v1, v8, v5, v7}, Llyiahf/vczjk/jm0;->OooOOo0(Llyiahf/vczjk/jm0;III)Llyiahf/vczjk/jm0;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/zp6;-><init>(Llyiahf/vczjk/jm0;)V

    return-object v0

    :cond_5
    if-ne v2, v7, :cond_6

    const-string v5, "prefix"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v3}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v5

    invoke-virtual {v1, v8, v3, v5}, Llyiahf/vczjk/jm0;->OooOOOO(ILlyiahf/vczjk/jm0;I)Z

    move-result v3

    if-eqz v3, :cond_6

    goto :goto_1

    :cond_6
    if-ne v2, v4, :cond_8

    invoke-virtual {p0}, Llyiahf/vczjk/zp6;->OooO0oo()Ljava/lang/Character;

    move-result-object v3

    if-eqz v3, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v0

    if-ne v0, v6, :cond_7

    goto :goto_1

    :cond_7
    new-instance v0, Llyiahf/vczjk/zp6;

    invoke-static {v1, v8, v6, v7}, Llyiahf/vczjk/jm0;->OooOOo0(Llyiahf/vczjk/jm0;III)Llyiahf/vczjk/jm0;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/zp6;-><init>(Llyiahf/vczjk/jm0;)V

    return-object v0

    :cond_8
    if-ne v2, v4, :cond_9

    new-instance v1, Llyiahf/vczjk/zp6;

    invoke-direct {v1, v0}, Llyiahf/vczjk/zp6;-><init>(Llyiahf/vczjk/jm0;)V

    return-object v1

    :cond_9
    if-nez v2, :cond_a

    new-instance v0, Llyiahf/vczjk/zp6;

    invoke-static {v1, v8, v7, v7}, Llyiahf/vczjk/jm0;->OooOOo0(Llyiahf/vczjk/jm0;III)Llyiahf/vczjk/jm0;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/zp6;-><init>(Llyiahf/vczjk/jm0;)V

    return-object v0

    :cond_a
    new-instance v0, Llyiahf/vczjk/zp6;

    invoke-static {v1, v8, v2, v7}, Llyiahf/vczjk/jm0;->OooOOo0(Llyiahf/vczjk/jm0;III)Llyiahf/vczjk/jm0;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/zp6;-><init>(Llyiahf/vczjk/jm0;)V

    return-object v0

    :cond_b
    :goto_1
    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/zp6;
    .locals 11

    const-string v0, "other"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/OooOO0;->OooO00o(Llyiahf/vczjk/zp6;)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, -0x1

    if-ne v0, v4, :cond_0

    move-object v5, v2

    goto :goto_0

    :cond_0
    new-instance v5, Llyiahf/vczjk/zp6;

    invoke-virtual {v1, v3, v0}, Llyiahf/vczjk/jm0;->OooOOOo(II)Llyiahf/vczjk/jm0;

    move-result-object v0

    invoke-direct {v5, v0}, Llyiahf/vczjk/zp6;-><init>(Llyiahf/vczjk/jm0;)V

    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/OooOO0;->OooO00o(Llyiahf/vczjk/zp6;)I

    move-result v0

    iget-object v6, p1, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    if-ne v0, v4, :cond_1

    goto :goto_1

    :cond_1
    new-instance v2, Llyiahf/vczjk/zp6;

    invoke-virtual {v6, v3, v0}, Llyiahf/vczjk/jm0;->OooOOOo(II)Llyiahf/vczjk/jm0;

    move-result-object v0

    invoke-direct {v2, v0}, Llyiahf/vczjk/zp6;-><init>(Llyiahf/vczjk/jm0;)V

    :goto_1
    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const-string v2, " and "

    if-eqz v0, :cond_8

    invoke-virtual {p0}, Llyiahf/vczjk/zp6;->OooO00o()Ljava/util/ArrayList;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/zp6;->OooO00o()Ljava/util/ArrayList;

    move-result-object v5

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v7

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v8

    invoke-static {v7, v8}, Ljava/lang/Math;->min(II)I

    move-result v7

    move v8, v3

    :goto_2
    if-ge v8, v7, :cond_2

    invoke-virtual {v0, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v9

    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_2

    add-int/lit8 v8, v8, 0x1

    goto :goto_2

    :cond_2
    if-ne v8, v7, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v1

    invoke-virtual {v6}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v6

    if-ne v1, v6, :cond_3

    const-string p1, "."

    invoke-static {p1, v3}, Llyiahf/vczjk/xj0;->OooOOOo(Ljava/lang/String;Z)Llyiahf/vczjk/zp6;

    move-result-object p1

    return-object p1

    :cond_3
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v1

    invoke-virtual {v5, v8, v1}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    move-result-object v1

    sget-object v6, Llyiahf/vczjk/OooOO0;->OooO0o0:Llyiahf/vczjk/jm0;

    invoke-interface {v1, v6}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    move-result v1

    if-ne v1, v4, :cond_7

    new-instance v1, Llyiahf/vczjk/yi0;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Llyiahf/vczjk/OooOO0;->OooO0OO(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/jm0;

    move-result-object p1

    if-nez p1, :cond_4

    invoke-static {p0}, Llyiahf/vczjk/OooOO0;->OooO0OO(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/jm0;

    move-result-object p1

    if-nez p1, :cond_4

    sget-object p1, Llyiahf/vczjk/zp6;->OooOOO:Ljava/lang/String;

    invoke-static {p1}, Llyiahf/vczjk/OooOO0;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/jm0;

    move-result-object p1

    :cond_4
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v2

    move v4, v8

    :goto_3
    if-ge v4, v2, :cond_5

    sget-object v5, Llyiahf/vczjk/OooOO0;->OooO0o0:Llyiahf/vczjk/jm0;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/yi0;->o00000oO(Llyiahf/vczjk/jm0;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/yi0;->o00000oO(Llyiahf/vczjk/jm0;)V

    add-int/lit8 v4, v4, 0x1

    goto :goto_3

    :cond_5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v2

    :goto_4
    if-ge v8, v2, :cond_6

    invoke-virtual {v0, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/jm0;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/yi0;->o00000oO(Llyiahf/vczjk/jm0;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/yi0;->o00000oO(Llyiahf/vczjk/jm0;)V

    add-int/lit8 v8, v8, 0x1

    goto :goto_4

    :cond_6
    invoke-static {v1, v3}, Llyiahf/vczjk/OooOO0;->OooO0Oo(Llyiahf/vczjk/yi0;Z)Llyiahf/vczjk/zp6;

    move-result-object p1

    return-object p1

    :cond_7
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Impossible relative path to resolve: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_8
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Paths of different roots cannot be relative to each other: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0o()Ljava/io/File;
    .locals 2

    new-instance v0, Ljava/io/File;

    iget-object v1, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooOOoo()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/zp6;
    .locals 1

    const-string v0, "child"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/yi0;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yi0;->o000OO(Ljava/lang/String;)V

    const/4 p1, 0x0

    invoke-static {v0, p1}, Llyiahf/vczjk/OooOO0;->OooO0Oo(Llyiahf/vczjk/yi0;Z)Llyiahf/vczjk/zp6;

    move-result-object v0

    invoke-static {p0, v0, p1}, Llyiahf/vczjk/OooOO0;->OooO0O0(Llyiahf/vczjk/zp6;Llyiahf/vczjk/zp6;Z)Llyiahf/vczjk/zp6;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oO()Ljava/nio/file/Path;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-virtual {v0}, Llyiahf/vczjk/jm0;->OooOOoo()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/String;

    invoke-static {v0, v1}, Llyiahf/vczjk/mh6;->OooO(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;

    move-result-object v0

    const-string v1, "get(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0oo()Ljava/lang/Character;
    .locals 3

    sget-object v0, Llyiahf/vczjk/OooOO0;->OooO00o:Llyiahf/vczjk/jm0;

    iget-object v1, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-static {v1, v0}, Llyiahf/vczjk/jm0;->OooO(Llyiahf/vczjk/jm0;Llyiahf/vczjk/jm0;)I

    move-result v0

    const/4 v2, -0x1

    if-eq v0, v2, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v0

    const/4 v2, 0x2

    if-ge v0, v2, :cond_1

    goto :goto_1

    :cond_1
    const/4 v0, 0x1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/jm0;->OooOO0O(I)B

    move-result v0

    const/16 v2, 0x3a

    if-eq v0, v2, :cond_2

    goto :goto_1

    :cond_2
    const/4 v0, 0x0

    invoke-virtual {v1, v0}, Llyiahf/vczjk/jm0;->OooOO0O(I)B

    move-result v0

    int-to-char v0, v0

    const/16 v1, 0x61

    if-gt v1, v0, :cond_3

    const/16 v1, 0x7b

    if-ge v0, v1, :cond_3

    goto :goto_0

    :cond_3
    const/16 v1, 0x41

    if-gt v1, v0, :cond_4

    const/16 v1, 0x5b

    if-ge v0, v1, :cond_4

    :goto_0
    invoke-static {v0}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object v0

    return-object v0

    :cond_4
    :goto_1
    const/4 v0, 0x0

    return-object v0
.end method

.method public final compareTo(Ljava/lang/Object;)I
    .locals 1

    check-cast p1, Llyiahf/vczjk/zp6;

    const-string v0, "other"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    iget-object p1, p1, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/jm0;->OooO0O0(Llyiahf/vczjk/jm0;)I

    move-result p1

    return p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/zp6;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/zp6;

    iget-object p1, p1, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    iget-object v0, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-virtual {v0}, Llyiahf/vczjk/jm0;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-virtual {v0}, Llyiahf/vczjk/jm0;->OooOOoo()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
