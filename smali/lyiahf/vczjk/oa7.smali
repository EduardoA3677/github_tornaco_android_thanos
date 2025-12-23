.class public final Llyiahf/vczjk/oa7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/nca;

.field public final OooO0OO:Ljava/util/HashMap;

.field public final OooO0Oo:[Llyiahf/vczjk/ph8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/nca;[Llyiahf/vczjk/ph8;ZZ)V
    .locals 5

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/oa7;->OooO0O0:Llyiahf/vczjk/nca;

    if-eqz p4, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object p2

    invoke-virtual {p2}, Llyiahf/vczjk/ec5;->OooOO0o()Ljava/util/Locale;

    move-result-object p2

    new-instance p4, Llyiahf/vczjk/na7;

    invoke-direct {p4, p2}, Llyiahf/vczjk/na7;-><init>(Ljava/util/Locale;)V

    iput-object p4, p0, Llyiahf/vczjk/oa7;->OooO0OO:Ljava/util/HashMap;

    goto :goto_0

    :cond_0
    new-instance p2, Ljava/util/HashMap;

    invoke-direct {p2}, Ljava/util/HashMap;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/oa7;->OooO0OO:Ljava/util/HashMap;

    :goto_0
    array-length p2, p3

    iput p2, p0, Llyiahf/vczjk/oa7;->OooO00o:I

    new-array p4, p2, [Llyiahf/vczjk/ph8;

    iput-object p4, p0, Llyiahf/vczjk/oa7;->OooO0Oo:[Llyiahf/vczjk/ph8;

    const/4 p4, 0x0

    if-eqz p5, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object p1

    array-length p5, p3

    move v0, p4

    :goto_1
    if-ge v0, p5, :cond_5

    aget-object v1, p3, v0

    invoke-virtual {v1}, Llyiahf/vczjk/ph8;->OooOo0O()Z

    move-result v2

    if-nez v2, :cond_4

    iget-object v2, v1, Llyiahf/vczjk/lh1;->OooOOO0:Ljava/util/List;

    if-nez v2, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-interface {v1}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v4

    if-eqz v4, :cond_1

    invoke-virtual {v3, v4}, Llyiahf/vczjk/yn;->OooOooO(Llyiahf/vczjk/pm;)Ljava/util/List;

    move-result-object v2

    :cond_1
    if-nez v2, :cond_2

    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    :cond_2
    iput-object v2, v1, Llyiahf/vczjk/lh1;->OooOOO0:Ljava/util/List;

    :cond_3
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_4

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xa7;

    iget-object v4, p0, Llyiahf/vczjk/oa7;->OooO0OO:Ljava/util/HashMap;

    invoke-virtual {v3}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v4, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_2

    :cond_4
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_5
    :goto_3
    if-ge p4, p2, :cond_7

    aget-object p1, p3, p4

    iget-object p5, p0, Llyiahf/vczjk/oa7;->OooO0Oo:[Llyiahf/vczjk/ph8;

    aput-object p1, p5, p4

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->OooOo0O()Z

    move-result p5

    if-nez p5, :cond_6

    iget-object p5, p0, Llyiahf/vczjk/oa7;->OooO0OO:Ljava/util/HashMap;

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p5, v0, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_6
    add-int/lit8 p4, p4, 0x1

    goto :goto_3

    :cond_7
    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/nca;[Llyiahf/vczjk/ph8;Z)Llyiahf/vczjk/oa7;
    .locals 7

    array-length v0, p2

    new-array v4, v0, [Llyiahf/vczjk/ph8;

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    aget-object v2, p2, v1

    invoke-virtual {v2}, Llyiahf/vczjk/ph8;->OooOOoo()Z

    move-result v3

    if-nez v3, :cond_0

    invoke-virtual {v2}, Llyiahf/vczjk/ph8;->getType()Llyiahf/vczjk/x64;

    move-result-object v3

    invoke-virtual {p0, v3, v2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ph8;->Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;

    move-result-object v2

    :cond_0
    aput-object v2, v4, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    new-instance v1, Llyiahf/vczjk/oa7;

    const/4 v6, 0x0

    move-object v2, p0

    move-object v3, p1

    move v5, p3

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/oa7;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/nca;[Llyiahf/vczjk/ph8;ZZ)V

    return-object v1
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/lb7;)Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/oa7;->OooO0O0:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, p2, Llyiahf/vczjk/lb7;->OooO0o0:I

    iget-object v2, p2, Llyiahf/vczjk/lb7;->OooO0Oo:[Ljava/lang/Object;

    const/4 v3, 0x0

    iget-object v4, p0, Llyiahf/vczjk/oa7;->OooO0Oo:[Llyiahf/vczjk/ph8;

    if-lez v1, :cond_2

    iget-object v1, p2, Llyiahf/vczjk/lb7;->OooO0oO:Ljava/util/BitSet;

    if-nez v1, :cond_1

    iget v1, p2, Llyiahf/vczjk/lb7;->OooO0o:I

    array-length v5, v2

    move v6, v3

    :goto_0
    if-ge v6, v5, :cond_2

    and-int/lit8 v7, v1, 0x1

    if-nez v7, :cond_0

    aget-object v7, v4, v6

    invoke-virtual {p2, v7}, Llyiahf/vczjk/lb7;->OooO00o(Llyiahf/vczjk/ph8;)Ljava/lang/Object;

    move-result-object v7

    aput-object v7, v2, v6

    :cond_0
    add-int/lit8 v6, v6, 0x1

    shr-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    array-length v5, v2

    move v6, v3

    :goto_1
    invoke-virtual {v1, v6}, Ljava/util/BitSet;->nextClearBit(I)I

    move-result v6

    if-ge v6, v5, :cond_2

    aget-object v7, v4, v6

    invoke-virtual {p2, v7}, Llyiahf/vczjk/lb7;->OooO00o(Llyiahf/vczjk/ph8;)Ljava/lang/Object;

    move-result-object v7

    aput-object v7, v2, v6

    add-int/lit8 v6, v6, 0x1

    goto :goto_1

    :cond_2
    sget-object v1, Llyiahf/vczjk/w72;->OooOoO0:Llyiahf/vczjk/w72;

    iget-object v5, p2, Llyiahf/vczjk/lb7;->OooO0O0:Llyiahf/vczjk/v72;

    invoke-virtual {v5, v1}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v1

    const/4 v6, 0x0

    if-eqz v1, :cond_4

    move v1, v3

    :goto_2
    array-length v7, v4

    if-ge v1, v7, :cond_4

    aget-object v7, v2, v1

    if-eqz v7, :cond_3

    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    :cond_3
    aget-object p1, v4, v1

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object p2

    aget-object v0, v4, v1

    invoke-virtual {v0}, Llyiahf/vczjk/ph8;->OooOOO0()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {p2, v0}, [Ljava/lang/Object;

    move-result-object p2

    const-string v0, "Null value for creator property \'%s\' (index %d); `DeserializationFeature.FAIL_ON_NULL_FOR_CREATOR_PARAMETERS` enabled"

    invoke-virtual {v5, p1, v0, p2}, Llyiahf/vczjk/v72;->o0000O(Llyiahf/vczjk/db0;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v6

    :cond_4
    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/nca;->OooOOOo(Llyiahf/vczjk/v72;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_7

    iget-object v1, p2, Llyiahf/vczjk/lb7;->OooO0OO:Llyiahf/vczjk/u66;

    if-eqz v1, :cond_6

    iget-object p2, p2, Llyiahf/vczjk/lb7;->OooO:Ljava/lang/Object;

    if-eqz p2, :cond_5

    iget-object v0, v1, Llyiahf/vczjk/u66;->generator:Llyiahf/vczjk/p66;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/v72;->o00Ooo(Ljava/lang/Object;Llyiahf/vczjk/p66;)Llyiahf/vczjk/bh7;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    throw v6

    :cond_5
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    iget-object v0, v1, Llyiahf/vczjk/u66;->propertyName:Llyiahf/vczjk/xa7;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v4, "No Object Id found for an instance of "

    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, ", to assign to property \'"

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, "\'"

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    iget-object v0, v1, Llyiahf/vczjk/u66;->idProperty:Llyiahf/vczjk/ph8;

    new-array v1, v3, [Ljava/lang/Object;

    invoke-virtual {p1, v0, p2, v1}, Llyiahf/vczjk/v72;->o0000O(Llyiahf/vczjk/db0;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v6

    :cond_6
    iget-object p1, p2, Llyiahf/vczjk/lb7;->OooO0oo:Llyiahf/vczjk/o0O00o00;

    :goto_3
    if-eqz p1, :cond_7

    invoke-virtual {p1, v0}, Llyiahf/vczjk/o0O00o00;->OooO0OO(Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/o0O00o00;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/o0O00o00;

    goto :goto_3

    :cond_7
    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/ph8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/oa7;->OooO0OO:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ph8;

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u66;)Llyiahf/vczjk/lb7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/lb7;

    iget v1, p0, Llyiahf/vczjk/oa7;->OooO00o:I

    invoke-direct {v0, p1, p2, v1, p3}, Llyiahf/vczjk/lb7;-><init>(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;ILlyiahf/vczjk/u66;)V

    return-object v0
.end method
