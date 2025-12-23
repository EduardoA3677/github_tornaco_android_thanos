.class public final Llyiahf/vczjk/r54;
.super Llyiahf/vczjk/yn;
.source "SourceFile"


# static fields
.field public static final OooOOO:[Ljava/lang/Class;

.field public static final OooOOOO:[Ljava/lang/Class;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public transient OooOOO0:Llyiahf/vczjk/kl4;

.field protected _cfgConstructorPropertiesImpliesCreator:Z


# direct methods
.method static constructor <clinit>()V
    .locals 9

    const-class v4, Llyiahf/vczjk/nb4;

    const-class v5, Llyiahf/vczjk/qc4;

    const-class v0, Llyiahf/vczjk/xb4;

    const-class v1, Llyiahf/vczjk/xc4;

    const-class v2, Llyiahf/vczjk/r94;

    const-class v3, Llyiahf/vczjk/nc4;

    const-class v6, Llyiahf/vczjk/z84;

    const-class v7, Llyiahf/vczjk/ka4;

    filled-new-array/range {v0 .. v7}, [Ljava/lang/Class;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/r54;->OooOOO:[Ljava/lang/Class;

    const-class v5, Llyiahf/vczjk/qc4;

    const-class v6, Llyiahf/vczjk/z84;

    const-class v1, Llyiahf/vczjk/c94;

    const-class v2, Llyiahf/vczjk/xc4;

    const-class v3, Llyiahf/vczjk/r94;

    const-class v4, Llyiahf/vczjk/nc4;

    const-class v7, Llyiahf/vczjk/ka4;

    const-class v8, Llyiahf/vczjk/oa4;

    filled-new-array/range {v1 .. v8}, [Ljava/lang/Class;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/r54;->OooOOOO:[Ljava/lang/Class;

    :try_start_0
    sget v0, Llyiahf/vczjk/x54;->OooO00o:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    return-void
.end method

.method public static o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;
    .locals 1

    if-eqz p0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/vy0;->OooOOo(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    return-object p0

    :cond_1
    :goto_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static o00o0O(Llyiahf/vczjk/fc5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/e59;
    .locals 4

    const-class v0, Llyiahf/vczjk/nc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nc4;

    const-class v1, Llyiahf/vczjk/pc4;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pc4;

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {v1}, Llyiahf/vczjk/pc4;->value()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v3

    invoke-static {v1, v3}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/b5a;

    goto :goto_1

    :cond_1
    if-nez v0, :cond_2

    :goto_0
    return-object v2

    :cond_2
    invoke-interface {v0}, Llyiahf/vczjk/nc4;->use()Llyiahf/vczjk/lc4;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/lc4;->OooOOO0:Llyiahf/vczjk/lc4;

    if-ne v1, v3, :cond_3

    new-instance p0, Llyiahf/vczjk/e59;

    invoke-direct {p0}, Llyiahf/vczjk/e59;-><init>()V

    iput-object v3, p0, Llyiahf/vczjk/e59;->OooO00o:Llyiahf/vczjk/lc4;

    iput-object v2, p0, Llyiahf/vczjk/e59;->OooO0o:Llyiahf/vczjk/d4a;

    invoke-virtual {v3}, Llyiahf/vczjk/lc4;->OooO00o()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/e59;->OooO0OO:Ljava/lang/String;

    return-object p0

    :cond_3
    new-instance v1, Llyiahf/vczjk/e59;

    invoke-direct {v1}, Llyiahf/vczjk/e59;-><init>()V

    :goto_1
    const-class v3, Llyiahf/vczjk/jc4;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/jc4;

    if-nez v3, :cond_4

    goto :goto_2

    :cond_4
    invoke-interface {v3}, Llyiahf/vczjk/jc4;->value()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result p0

    invoke-static {v2, p0}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object p0

    move-object v2, p0

    check-cast v2, Llyiahf/vczjk/d4a;

    :goto_2
    invoke-interface {v0}, Llyiahf/vczjk/nc4;->use()Llyiahf/vczjk/lc4;

    move-result-object p0

    check-cast v1, Llyiahf/vczjk/e59;

    if-eqz p0, :cond_a

    iput-object p0, v1, Llyiahf/vczjk/e59;->OooO00o:Llyiahf/vczjk/lc4;

    iput-object v2, v1, Llyiahf/vczjk/e59;->OooO0o:Llyiahf/vczjk/d4a;

    invoke-virtual {p0}, Llyiahf/vczjk/lc4;->OooO00o()Ljava/lang/String;

    move-result-object p0

    iput-object p0, v1, Llyiahf/vczjk/e59;->OooO0OO:Ljava/lang/String;

    invoke-interface {v0}, Llyiahf/vczjk/nc4;->include()Llyiahf/vczjk/kc4;

    move-result-object p0

    sget-object v2, Llyiahf/vczjk/kc4;->OooOOOo:Llyiahf/vczjk/kc4;

    if-ne p0, v2, :cond_5

    instance-of p1, p1, Llyiahf/vczjk/hm;

    if-eqz p1, :cond_5

    sget-object p0, Llyiahf/vczjk/kc4;->OooOOO0:Llyiahf/vczjk/kc4;

    :cond_5
    if-eqz p0, :cond_9

    iput-object p0, v1, Llyiahf/vczjk/e59;->OooO0O0:Llyiahf/vczjk/kc4;

    invoke-interface {v0}, Llyiahf/vczjk/nc4;->property()Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_6

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p1

    if-nez p1, :cond_7

    :cond_6
    iget-object p0, v1, Llyiahf/vczjk/e59;->OooO00o:Llyiahf/vczjk/lc4;

    invoke-virtual {p0}, Llyiahf/vczjk/lc4;->OooO00o()Ljava/lang/String;

    move-result-object p0

    :cond_7
    iput-object p0, v1, Llyiahf/vczjk/e59;->OooO0OO:Ljava/lang/String;

    invoke-interface {v0}, Llyiahf/vczjk/nc4;->defaultImpl()Ljava/lang/Class;

    move-result-object p0

    const-class p1, Llyiahf/vczjk/mc4;

    if-eq p0, p1, :cond_8

    invoke-virtual {p0}, Ljava/lang/Class;->isAnnotation()Z

    move-result p1

    if-nez p1, :cond_8

    iput-object p0, v1, Llyiahf/vczjk/e59;->OooO0o0:Ljava/lang/Class;

    :cond_8
    invoke-interface {v0}, Llyiahf/vczjk/nc4;->visible()Z

    move-result p0

    iput-boolean p0, v1, Llyiahf/vczjk/e59;->OooO0Oo:Z

    return-object v1

    :cond_9
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "includeAs cannot be null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_a
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "idType cannot be null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static o00ooo(Ljava/lang/Class;Ljava/lang/Class;)Z
    .locals 1

    invoke-virtual {p0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0O(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    if-ne p0, p1, :cond_1

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/vy0;->OooOo0O(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p0

    if-ne p1, p0, :cond_1

    :goto_0
    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static oo000o(Ljava/lang/Class;Llyiahf/vczjk/x64;)Z
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->o00O0O()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/vy0;->OooOo0O(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p0

    return p0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0O(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    if-ne p0, p1, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 2

    const-class v0, Llyiahf/vczjk/c94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c94;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/c94;->converter()Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_2

    const-class v1, Llyiahf/vczjk/ep1;

    if-ne p1, v1, :cond_1

    goto :goto_0

    :cond_1
    return-object p1

    :cond_2
    :goto_0
    return-object v0
.end method

.method public final OooO00o(Llyiahf/vczjk/gg8;Llyiahf/vczjk/hm;Ljava/util/ArrayList;)V
    .locals 17

    move-object/from16 v0, p1

    move-object/from16 v1, p2

    move-object/from16 v2, p3

    iget-object v3, v1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v4, Llyiahf/vczjk/v84;

    invoke-interface {v3, v4}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/v84;

    if-nez v3, :cond_0

    goto/16 :goto_8

    :cond_0
    invoke-interface {v3}, Llyiahf/vczjk/v84;->prepend()Z

    move-result v4

    invoke-interface {v3}, Llyiahf/vczjk/v84;->attrs()[Llyiahf/vczjk/t84;

    move-result-object v5

    array-length v6, v5

    const/4 v7, 0x0

    const/4 v8, 0x0

    move v9, v7

    :goto_0
    iget-object v10, v1, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    if-ge v9, v6, :cond_8

    if-nez v8, :cond_1

    const-class v8, Ljava/lang/Object;

    invoke-virtual {v0, v8}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v8

    :cond_1
    aget-object v11, v5, v9

    invoke-interface {v11}, Llyiahf/vczjk/t84;->required()Z

    move-result v12

    if-eqz v12, :cond_2

    sget-object v12, Llyiahf/vczjk/wa7;->OooOOO:Llyiahf/vczjk/wa7;

    goto :goto_1

    :cond_2
    sget-object v12, Llyiahf/vczjk/wa7;->OooOOOO:Llyiahf/vczjk/wa7;

    :goto_1
    invoke-interface {v11}, Llyiahf/vczjk/t84;->value()Ljava/lang/String;

    move-result-object v13

    invoke-interface {v11}, Llyiahf/vczjk/t84;->propName()Ljava/lang/String;

    move-result-object v14

    invoke-interface {v11}, Llyiahf/vczjk/t84;->propNamespace()Ljava/lang/String;

    move-result-object v15

    invoke-virtual {v14}, Ljava/lang/String;->isEmpty()Z

    move-result v16

    if-eqz v16, :cond_3

    sget-object v14, Llyiahf/vczjk/xa7;->OooOOO0:Llyiahf/vczjk/xa7;

    goto :goto_3

    :cond_3
    if-eqz v15, :cond_5

    invoke-virtual {v15}, Ljava/lang/String;->isEmpty()Z

    move-result v16

    if-eqz v16, :cond_4

    goto :goto_2

    :cond_4
    invoke-static {v14, v15}, Llyiahf/vczjk/xa7;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v14

    goto :goto_3

    :cond_5
    :goto_2
    invoke-static {v14}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v14

    :goto_3
    invoke-virtual {v14}, Llyiahf/vczjk/xa7;->OooO0Oo()Z

    move-result v15

    if-nez v15, :cond_6

    invoke-static {v13}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v14

    :cond_6
    new-instance v15, Llyiahf/vczjk/qja;

    invoke-direct {v15, v1, v10, v13, v8}, Llyiahf/vczjk/qja;-><init>(Llyiahf/vczjk/hm;Ljava/lang/Class;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    invoke-interface {v11}, Llyiahf/vczjk/t84;->include()Llyiahf/vczjk/ea4;

    move-result-object v10

    invoke-static {v0, v15, v14, v12, v10}, Llyiahf/vczjk/bo8;->OooOoOO(Llyiahf/vczjk/gg8;Llyiahf/vczjk/qja;Llyiahf/vczjk/xa7;Llyiahf/vczjk/wa7;Llyiahf/vczjk/ea4;)Llyiahf/vczjk/bo8;

    move-result-object v10

    new-instance v11, Llyiahf/vczjk/l10;

    iget-object v12, v1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    invoke-direct {v11, v13, v10, v12, v8}, Llyiahf/vczjk/l10;-><init>(Ljava/lang/String;Llyiahf/vczjk/bo8;Llyiahf/vczjk/lo;Llyiahf/vczjk/x64;)V

    if-eqz v4, :cond_7

    invoke-interface {v2, v9, v11}, Ljava/util/List;->add(ILjava/lang/Object;)V

    goto :goto_4

    :cond_7
    invoke-interface {v2, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_4
    add-int/lit8 v9, v9, 0x1

    goto :goto_0

    :cond_8
    invoke-interface {v3}, Llyiahf/vczjk/v84;->props()[Llyiahf/vczjk/u84;

    move-result-object v2

    array-length v3, v2

    if-lez v3, :cond_d

    aget-object v2, v2, v7

    invoke-interface {v2}, Llyiahf/vczjk/u84;->required()Z

    move-result v3

    if-eqz v3, :cond_9

    sget-object v3, Llyiahf/vczjk/wa7;->OooOOO:Llyiahf/vczjk/wa7;

    goto :goto_5

    :cond_9
    sget-object v3, Llyiahf/vczjk/wa7;->OooOOOO:Llyiahf/vczjk/wa7;

    :goto_5
    invoke-interface {v2}, Llyiahf/vczjk/u84;->name()Ljava/lang/String;

    move-result-object v4

    invoke-interface {v2}, Llyiahf/vczjk/u84;->namespace()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4}, Ljava/lang/String;->isEmpty()Z

    move-result v6

    if-nez v6, :cond_c

    if-eqz v5, :cond_b

    invoke-virtual {v5}, Ljava/lang/String;->isEmpty()Z

    move-result v6

    if-eqz v6, :cond_a

    goto :goto_6

    :cond_a
    invoke-static {v4, v5}, Llyiahf/vczjk/xa7;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v4

    goto :goto_7

    :cond_b
    :goto_6
    invoke-static {v4}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v4

    goto :goto_7

    :cond_c
    sget-object v4, Llyiahf/vczjk/xa7;->OooOOO0:Llyiahf/vczjk/xa7;

    :goto_7
    invoke-interface {v2}, Llyiahf/vczjk/u84;->type()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v0, v5}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v5

    new-instance v6, Llyiahf/vczjk/qja;

    invoke-virtual {v4}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v7

    invoke-direct {v6, v1, v10, v7, v5}, Llyiahf/vczjk/qja;-><init>(Llyiahf/vczjk/hm;Ljava/lang/Class;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    invoke-interface {v2}, Llyiahf/vczjk/u84;->include()Llyiahf/vczjk/ea4;

    move-result-object v1

    invoke-static {v0, v6, v4, v3, v1}, Llyiahf/vczjk/bo8;->OooOoOO(Llyiahf/vczjk/gg8;Llyiahf/vczjk/qja;Llyiahf/vczjk/xa7;Llyiahf/vczjk/wa7;Llyiahf/vczjk/ea4;)Llyiahf/vczjk/bo8;

    invoke-interface {v2}, Llyiahf/vczjk/u84;->value()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    invoke-static {v1, v0}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rja;

    check-cast v0, Llyiahf/vczjk/l10;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Should not be called on this type"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_d
    :goto_8
    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/hm;Llyiahf/vczjk/gka;)Llyiahf/vczjk/gka;
    .locals 9

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/y84;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/y84;

    if-nez p1, :cond_0

    return-object p2

    :cond_0
    check-cast p2, Llyiahf/vczjk/fka;

    iget-object v0, p2, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    invoke-interface {p1}, Llyiahf/vczjk/y84;->getterVisibility()Llyiahf/vczjk/x84;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/x84;->OooOOOo:Llyiahf/vczjk/x84;

    if-ne v1, v2, :cond_1

    move-object v4, v0

    goto :goto_0

    :cond_1
    move-object v4, v1

    :goto_0
    iget-object v0, p2, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    invoke-interface {p1}, Llyiahf/vczjk/y84;->isGetterVisibility()Llyiahf/vczjk/x84;

    move-result-object v1

    if-ne v1, v2, :cond_2

    move-object v5, v0

    goto :goto_1

    :cond_2
    move-object v5, v1

    :goto_1
    iget-object v0, p2, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    invoke-interface {p1}, Llyiahf/vczjk/y84;->setterVisibility()Llyiahf/vczjk/x84;

    move-result-object v1

    if-ne v1, v2, :cond_3

    move-object v6, v0

    goto :goto_2

    :cond_3
    move-object v6, v1

    :goto_2
    iget-object v0, p2, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    invoke-interface {p1}, Llyiahf/vczjk/y84;->creatorVisibility()Llyiahf/vczjk/x84;

    move-result-object v1

    if-ne v1, v2, :cond_4

    move-object v7, v0

    goto :goto_3

    :cond_4
    move-object v7, v1

    :goto_3
    iget-object v0, p2, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    invoke-interface {p1}, Llyiahf/vczjk/y84;->fieldVisibility()Llyiahf/vczjk/x84;

    move-result-object p1

    if-ne p1, v2, :cond_5

    move-object v8, v0

    goto :goto_4

    :cond_5
    move-object v8, p1

    :goto_4
    iget-object p1, p2, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    if-ne v4, p1, :cond_6

    iget-object p1, p2, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    if-ne v5, p1, :cond_6

    iget-object p1, p2, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    if-ne v6, p1, :cond_6

    iget-object p1, p2, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    if-ne v7, p1, :cond_6

    iget-object p1, p2, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    if-ne v8, p1, :cond_6

    goto :goto_5

    :cond_6
    new-instance v3, Llyiahf/vczjk/fka;

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/fka;-><init>(Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;)V

    move-object p2, v3

    :goto_5
    return-object p2
.end method

.method public final OooO0OO(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 1

    const-class v0, Llyiahf/vczjk/c94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c94;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/c94;->contentUsing()Ljava/lang/Class;

    move-result-object p1

    const-class v0, Llyiahf/vczjk/d94;

    if-eq p1, v0, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 1

    const-class v0, Llyiahf/vczjk/xb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xb4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/xb4;->contentUsing()Ljava/lang/Class;

    move-result-object p1

    const-class v0, Llyiahf/vczjk/yb4;

    if-eq p1, v0, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/u34;)Llyiahf/vczjk/a94;
    .locals 1

    const-class v0, Llyiahf/vczjk/b94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b94;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/b94;->mode()Llyiahf/vczjk/a94;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/a94;
    .locals 1

    const-class v0, Llyiahf/vczjk/b94;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/b94;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/b94;->mode()Llyiahf/vczjk/a94;

    move-result-object p1

    return-object p1

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/r54;->_cfgConstructorPropertiesImpliesCreator:Z

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/gc5;->OooOo:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result p1

    if-eqz p1, :cond_1

    instance-of p1, p2, Llyiahf/vczjk/jm;

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0oO(Ljava/lang/Class;)Ljava/lang/Enum;
    .locals 10

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    invoke-virtual {p1}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object v0

    array-length v1, v0

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_2

    aget-object v4, v0, v3

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->isEnumConstant()Z

    move-result v5

    if-eqz v5, :cond_1

    const-class v5, Llyiahf/vczjk/j94;

    invoke-virtual {v4, v5}, Ljava/lang/reflect/Field;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v5

    if-eqz v5, :cond_1

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p1}, Ljava/lang/Class;->getEnumConstants()[Ljava/lang/Object;

    move-result-object v5

    check-cast v5, [Ljava/lang/Enum;

    array-length v6, v5

    move v7, v2

    :goto_1
    if-ge v7, v6, :cond_1

    aget-object v8, v5, v7

    invoke-virtual {v8}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v9

    invoke-virtual {v4, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_0

    return-object v8

    :cond_0
    add-int/lit8 v7, v7, 0x1

    goto :goto_1

    :cond_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0oo(Llyiahf/vczjk/pm;)Ljava/lang/Object;
    .locals 2

    const-class v0, Llyiahf/vczjk/c94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c94;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/c94;->contentConverter()Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_2

    const-class v1, Llyiahf/vczjk/ep1;

    if-ne p1, v1, :cond_1

    goto :goto_0

    :cond_1
    return-object p1

    :cond_2
    :goto_0
    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 1

    const-class v0, Llyiahf/vczjk/c94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c94;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/c94;->using()Ljava/lang/Class;

    move-result-object p1

    const-class v0, Llyiahf/vczjk/d94;

    if-eq p1, v0, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOO0O(Ljava/lang/Class;[Ljava/lang/Enum;[[Ljava/lang/String;)V
    .locals 8

    invoke-virtual {p1}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object p1

    array-length v0, p1

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v2, v0, :cond_2

    aget-object v3, p1, v2

    invoke-virtual {v3}, Ljava/lang/reflect/Field;->isEnumConstant()Z

    move-result v4

    if-eqz v4, :cond_1

    const-class v4, Llyiahf/vczjk/q84;

    invoke-virtual {v3, v4}, Ljava/lang/reflect/Field;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/q84;

    if-eqz v4, :cond_1

    invoke-interface {v4}, Llyiahf/vczjk/q84;->value()[Ljava/lang/String;

    move-result-object v4

    array-length v5, v4

    if-eqz v5, :cond_1

    invoke-virtual {v3}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v3

    array-length v5, p2

    move v6, v1

    :goto_1
    if-ge v6, v5, :cond_1

    aget-object v7, p2, v6

    invoke-virtual {v7}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v3, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_0

    aput-object v4, p3, v6

    :cond_0
    add-int/lit8 v6, v6, 0x1

    goto :goto_1

    :cond_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public final OooOO0o(Ljava/lang/Class;[Ljava/lang/Enum;[Ljava/lang/String;)[Ljava/lang/String;
    .locals 7

    invoke-virtual {p1}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object p1

    array-length v0, p1

    const/4 v1, 0x0

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v0, :cond_4

    aget-object v4, p1, v3

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->isEnumConstant()Z

    move-result v5

    if-nez v5, :cond_0

    goto :goto_1

    :cond_0
    const-class v5, Llyiahf/vczjk/kb4;

    invoke-virtual {v4, v5}, Ljava/lang/reflect/Field;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/kb4;

    if-nez v5, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {v5}, Llyiahf/vczjk/kb4;->value()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/String;->isEmpty()Z

    move-result v6

    if-eqz v6, :cond_2

    goto :goto_1

    :cond_2
    if-nez v1, :cond_3

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    :cond_3
    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v1, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_4
    if-eqz v1, :cond_6

    array-length p1, p2

    :goto_2
    if-ge v2, p1, :cond_6

    aget-object v0, p2, v2

    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_5

    aput-object v0, p3, v2

    :cond_5
    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_6
    return-object p3
.end method

.method public final OooOOO(Llyiahf/vczjk/u34;)Llyiahf/vczjk/q94;
    .locals 14

    const-class v0, Llyiahf/vczjk/r94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r94;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    new-instance v1, Llyiahf/vczjk/q94;

    invoke-interface {p1}, Llyiahf/vczjk/r94;->pattern()Ljava/lang/String;

    move-result-object v2

    invoke-interface {p1}, Llyiahf/vczjk/r94;->shape()Llyiahf/vczjk/p94;

    move-result-object v3

    invoke-interface {p1}, Llyiahf/vczjk/r94;->locale()Ljava/lang/String;

    move-result-object v4

    invoke-interface {p1}, Llyiahf/vczjk/r94;->timezone()Ljava/lang/String;

    move-result-object v5

    invoke-interface {p1}, Llyiahf/vczjk/r94;->with()[Llyiahf/vczjk/n94;

    move-result-object v6

    invoke-interface {p1}, Llyiahf/vczjk/r94;->without()[Llyiahf/vczjk/n94;

    move-result-object v7

    array-length v8, v6

    const/4 v9, 0x0

    move v10, v9

    move v11, v10

    :goto_0
    const/4 v12, 0x1

    if-ge v10, v8, :cond_1

    aget-object v13, v6, v10

    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    move-result v13

    shl-int/2addr v12, v13

    or-int/2addr v11, v12

    add-int/lit8 v10, v10, 0x1

    goto :goto_0

    :cond_1
    array-length v6, v7

    move v8, v9

    :goto_1
    if-ge v9, v6, :cond_2

    aget-object v10, v7, v9

    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    move-result v10

    shl-int v10, v12, v10

    or-int/2addr v8, v10

    add-int/lit8 v9, v9, 0x1

    goto :goto_1

    :cond_2
    new-instance v6, Llyiahf/vczjk/o94;

    invoke-direct {v6, v11, v8}, Llyiahf/vczjk/o94;-><init>(II)V

    invoke-interface {p1}, Llyiahf/vczjk/r94;->lenient()Llyiahf/vczjk/df6;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/df6;->OooOOO:Llyiahf/vczjk/df6;

    if-ne p1, v7, :cond_3

    :goto_2
    move-object v7, v0

    goto :goto_3

    :cond_3
    sget-object v0, Llyiahf/vczjk/df6;->OooOOO0:Llyiahf/vczjk/df6;

    if-ne p1, v0, :cond_4

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    goto :goto_2

    :cond_4
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    goto :goto_2

    :goto_3
    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/q94;-><init>(Ljava/lang/String;Llyiahf/vczjk/p94;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/o94;Ljava/lang/Boolean;)V

    return-object v1
.end method

.method public final OooOOO0(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 1

    const-class v0, Llyiahf/vczjk/m94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/m94;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/m94;->value()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    if-lez v0, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOOOO(Llyiahf/vczjk/pm;)V
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/vm;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/vm;

    iget-object p1, p1, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    :cond_0
    return-void
.end method

.method public final OooOOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/t54;
    .locals 4

    const-class v0, Llyiahf/vczjk/u54;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/u54;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    invoke-interface {v0}, Llyiahf/vczjk/u54;->value()Ljava/lang/String;

    move-result-object v2

    invoke-interface {v0}, Llyiahf/vczjk/u54;->useInput()Llyiahf/vczjk/df6;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v3, Llyiahf/vczjk/df6;->OooOOO:Llyiahf/vczjk/df6;

    if-ne v0, v3, :cond_1

    move-object v0, v1

    goto :goto_0

    :cond_1
    sget-object v3, Llyiahf/vczjk/df6;->OooOOO0:Llyiahf/vczjk/df6;

    if-ne v0, v3, :cond_2

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    goto :goto_0

    :cond_2
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_0
    const-string v3, ""

    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    goto :goto_1

    :cond_3
    move-object v1, v2

    :goto_1
    if-nez v1, :cond_4

    if-nez v0, :cond_4

    sget-object v0, Llyiahf/vczjk/t54;->OooOOO0:Llyiahf/vczjk/t54;

    goto :goto_2

    :cond_4
    new-instance v2, Llyiahf/vczjk/t54;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/t54;-><init>(Ljava/lang/Object;Ljava/lang/Boolean;)V

    move-object v0, v2

    :goto_2
    iget-object v1, v0, Llyiahf/vczjk/t54;->_id:Ljava/lang/Object;

    if-eqz v1, :cond_5

    const/4 v1, 0x1

    goto :goto_3

    :cond_5
    const/4 v1, 0x0

    :goto_3
    if-nez v1, :cond_9

    instance-of v1, p1, Llyiahf/vczjk/rm;

    if-nez v1, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/u34;->OooOoOO()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    goto :goto_4

    :cond_6
    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/rm;

    invoke-virtual {v1}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v2

    array-length v2, v2

    if-nez v2, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/u34;->OooOoOO()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    goto :goto_4

    :cond_7
    invoke-virtual {v1}, Llyiahf/vczjk/rm;->o000000o()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    :goto_4
    iget-object v1, v0, Llyiahf/vczjk/t54;->_id:Ljava/lang/Object;

    invoke-virtual {p1, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_8

    goto :goto_5

    :cond_8
    new-instance v1, Llyiahf/vczjk/t54;

    iget-object v0, v0, Llyiahf/vczjk/t54;->_useInput:Ljava/lang/Boolean;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/t54;-><init>(Ljava/lang/Object;Ljava/lang/Boolean;)V

    move-object v0, v1

    :cond_9
    :goto_5
    return-object v0
.end method

.method public final OooOOo(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 1

    const-class v0, Llyiahf/vczjk/c94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c94;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/c94;->keyUsing()Ljava/lang/Class;

    move-result-object p1

    const-class v0, Llyiahf/vczjk/si4;

    if-eq p1, v0, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOOo0(Llyiahf/vczjk/pm;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/r54;->OooOOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/t54;

    move-result-object p1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/t54;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOoo(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 1

    const-class v0, Llyiahf/vczjk/xb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xb4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/xb4;->keyUsing()Ljava/lang/Class;

    move-result-object p1

    const-class v0, Llyiahf/vczjk/yb4;

    if-eq p1, v0, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOo(Llyiahf/vczjk/pm;)Ljava/lang/Object;
    .locals 1

    const-class v0, Llyiahf/vczjk/xb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xb4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/xb4;->nullsUsing()Ljava/lang/Class;

    move-result-object p1

    const-class v0, Llyiahf/vczjk/yb4;

    if-eq p1, v0, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOo0(Llyiahf/vczjk/pm;)Llyiahf/vczjk/xa7;
    .locals 2

    const-class v0, Llyiahf/vczjk/bc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/bc4;

    if-eqz v0, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/bc4;->value()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object p1

    return-object p1

    :cond_1
    const/4 v0, 0x0

    :goto_0
    const-class v1, Llyiahf/vczjk/kb4;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kb4;

    if-eqz v1, :cond_2

    invoke-interface {v1}, Llyiahf/vczjk/kb4;->value()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object p1

    return-object p1

    :cond_2
    if-nez v0, :cond_4

    sget-object v0, Llyiahf/vczjk/r54;->OooOOOO:[Ljava/lang/Class;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->o0OOO0o([Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_3

    goto :goto_1

    :cond_3
    const/4 p1, 0x0

    return-object p1

    :cond_4
    :goto_1
    sget-object p1, Llyiahf/vczjk/xa7;->OooOOO0:Llyiahf/vczjk/xa7;

    return-object p1
.end method

.method public final OooOo00(Llyiahf/vczjk/pm;)Ljava/lang/Boolean;
    .locals 2

    const-class v0, Llyiahf/vczjk/oa4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oa4;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/oa4;->value()Llyiahf/vczjk/df6;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/df6;->OooOOO:Llyiahf/vczjk/df6;

    if-ne p1, v1, :cond_1

    return-object v0

    :cond_1
    sget-object v0, Llyiahf/vczjk/df6;->OooOOO0:Llyiahf/vczjk/df6;

    if-ne p1, v0, :cond_2

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :cond_2
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1
.end method

.method public final OooOo0O(Llyiahf/vczjk/pm;)Llyiahf/vczjk/xa7;
    .locals 2

    const-class v0, Llyiahf/vczjk/w94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/w94;

    if-eqz v0, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/w94;->value()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 v0, 0x1

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    const-class v1, Llyiahf/vczjk/kb4;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kb4;

    if-eqz v1, :cond_2

    invoke-interface {v1}, Llyiahf/vczjk/kb4;->value()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object p1

    return-object p1

    :cond_2
    if-nez v0, :cond_4

    sget-object v0, Llyiahf/vczjk/r54;->OooOOO:[Ljava/lang/Class;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->o0OOO0o([Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_3

    goto :goto_1

    :cond_3
    const/4 p1, 0x0

    return-object p1

    :cond_4
    :goto_1
    sget-object p1, Llyiahf/vczjk/xa7;->OooOOO0:Llyiahf/vczjk/xa7;

    return-object p1
.end method

.method public final OooOo0o(Llyiahf/vczjk/hm;)Ljava/lang/Object;
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/pa4;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/pa4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/pa4;->value()Ljava/lang/Class;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/u34;Llyiahf/vczjk/t66;)Llyiahf/vczjk/t66;
    .locals 6

    const-class v0, Llyiahf/vczjk/z94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z94;

    if-nez p1, :cond_0

    return-object p2

    :cond_0
    if-nez p2, :cond_1

    sget-object p2, Llyiahf/vczjk/t66;->OooO0o:Llyiahf/vczjk/t66;

    :cond_1
    invoke-interface {p1}, Llyiahf/vczjk/z94;->alwaysAsId()Z

    move-result v4

    iget-boolean p1, p2, Llyiahf/vczjk/t66;->OooO0o0:Z

    if-ne p1, v4, :cond_2

    return-object p2

    :cond_2
    new-instance v0, Llyiahf/vczjk/t66;

    iget-object v1, p2, Llyiahf/vczjk/t66;->OooO00o:Llyiahf/vczjk/xa7;

    iget-object v5, p2, Llyiahf/vczjk/t66;->OooO0OO:Ljava/lang/Class;

    iget-object v2, p2, Llyiahf/vczjk/t66;->OooO0Oo:Ljava/lang/Class;

    iget-object v3, p2, Llyiahf/vczjk/t66;->OooO0O0:Ljava/lang/Class;

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/t66;-><init>(Llyiahf/vczjk/xa7;Ljava/lang/Class;Ljava/lang/Class;ZLjava/lang/Class;)V

    return-object v0
.end method

.method public final OooOoO0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/t66;
    .locals 7

    const-class v0, Llyiahf/vczjk/y94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/y94;

    if-eqz p1, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/y94;->generator()Ljava/lang/Class;

    move-result-object v0

    const-class v1, Llyiahf/vczjk/r66;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/y94;->property()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v2

    new-instance v1, Llyiahf/vczjk/t66;

    invoke-interface {p1}, Llyiahf/vczjk/y94;->scope()Ljava/lang/Class;

    move-result-object v3

    invoke-interface {p1}, Llyiahf/vczjk/y94;->generator()Ljava/lang/Class;

    move-result-object v4

    invoke-interface {p1}, Llyiahf/vczjk/y94;->resolver()Ljava/lang/Class;

    move-result-object v6

    const/4 v5, 0x0

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/t66;-><init>(Llyiahf/vczjk/xa7;Ljava/lang/Class;Ljava/lang/Class;ZLjava/lang/Class;)V

    return-object v1

    :cond_1
    :goto_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOoOO(Llyiahf/vczjk/hm;)Ljava/lang/Class;
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/c94;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c94;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/c94;->builder()Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoo(Llyiahf/vczjk/u34;)Llyiahf/vczjk/jb4;
    .locals 1

    const-class v0, Llyiahf/vczjk/kb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kb4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/kb4;->access()Llyiahf/vczjk/jb4;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOoo0(Llyiahf/vczjk/hm;)Llyiahf/vczjk/ya4;
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/za4;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/za4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/ya4;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ya4;-><init>(Llyiahf/vczjk/za4;)V

    return-object v0
.end method

.method public final OooOooO(Llyiahf/vczjk/pm;)Ljava/util/List;
    .locals 4

    const-class v0, Llyiahf/vczjk/q84;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/q84;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/q84;->value()[Ljava/lang/String;

    move-result-object p1

    array-length v0, p1

    if-nez v0, :cond_1

    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    return-object p1

    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_2

    aget-object v3, p1, v2

    invoke-static {v3}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    return-object v1
.end method

.method public final OooOooo(Llyiahf/vczjk/fc5;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;
    .locals 1

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {p1, p2}, Llyiahf/vczjk/r54;->o00o0O(Llyiahf/vczjk/fc5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/e59;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "Must call method with a container or reference type (got "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p3, ")"

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final Oooo(Llyiahf/vczjk/hm;)[Ljava/lang/String;
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/mb4;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mb4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/mb4;->value()[Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/fa4;
    .locals 7

    const-class v0, Llyiahf/vczjk/ga4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ga4;

    sget-object v1, Llyiahf/vczjk/ea4;->OooOOo0:Llyiahf/vczjk/ea4;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    goto :goto_1

    :cond_0
    sget-object v2, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    invoke-interface {v0}, Llyiahf/vczjk/ga4;->value()Llyiahf/vczjk/ea4;

    move-result-object v3

    invoke-interface {v0}, Llyiahf/vczjk/ga4;->content()Llyiahf/vczjk/ea4;

    move-result-object v4

    if-ne v3, v1, :cond_1

    if-ne v4, v1, :cond_1

    move-object v0, v2

    goto :goto_1

    :cond_1
    invoke-interface {v0}, Llyiahf/vczjk/ga4;->valueFilter()Ljava/lang/Class;

    move-result-object v2

    const/4 v5, 0x0

    const-class v6, Ljava/lang/Void;

    if-ne v2, v6, :cond_2

    move-object v2, v5

    :cond_2
    invoke-interface {v0}, Llyiahf/vczjk/ga4;->contentFilter()Ljava/lang/Class;

    move-result-object v0

    if-ne v0, v6, :cond_3

    goto :goto_0

    :cond_3
    move-object v5, v0

    :goto_0
    new-instance v0, Llyiahf/vczjk/fa4;

    invoke-direct {v0, v3, v4, v2, v5}, Llyiahf/vczjk/fa4;-><init>(Llyiahf/vczjk/ea4;Llyiahf/vczjk/ea4;Ljava/lang/Class;Ljava/lang/Class;)V

    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/fa4;->OooO0OO()Llyiahf/vczjk/ea4;

    move-result-object v2

    if-ne v2, v1, :cond_8

    const-class v1, Llyiahf/vczjk/xb4;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xb4;

    if-eqz p1, :cond_8

    invoke-interface {p1}, Llyiahf/vczjk/xb4;->include()Llyiahf/vczjk/vb4;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_7

    const/4 v1, 0x1

    if-eq p1, v1, :cond_6

    const/4 v1, 0x2

    if-eq p1, v1, :cond_5

    const/4 v1, 0x3

    if-eq p1, v1, :cond_4

    goto :goto_2

    :cond_4
    sget-object p1, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fa4;->OooO0o0(Llyiahf/vczjk/ea4;)Llyiahf/vczjk/fa4;

    move-result-object p1

    return-object p1

    :cond_5
    sget-object p1, Llyiahf/vczjk/ea4;->OooOOOo:Llyiahf/vczjk/ea4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fa4;->OooO0o0(Llyiahf/vczjk/ea4;)Llyiahf/vczjk/fa4;

    move-result-object p1

    return-object p1

    :cond_6
    sget-object p1, Llyiahf/vczjk/ea4;->OooOOO:Llyiahf/vczjk/ea4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fa4;->OooO0o0(Llyiahf/vczjk/ea4;)Llyiahf/vczjk/fa4;

    move-result-object p1

    return-object p1

    :cond_7
    sget-object p1, Llyiahf/vczjk/ea4;->OooOOO0:Llyiahf/vczjk/ea4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fa4;->OooO0o0(Llyiahf/vczjk/ea4;)Llyiahf/vczjk/fa4;

    move-result-object p1

    return-object p1

    :cond_8
    :goto_2
    return-object v0
.end method

.method public final Oooo000(Llyiahf/vczjk/pm;)Ljava/lang/String;
    .locals 1

    const-class v0, Llyiahf/vczjk/kb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kb4;

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/kb4;->defaultValue()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    :goto_0
    const/4 p1, 0x0

    :cond_1
    return-object p1
.end method

.method public final Oooo00O(Llyiahf/vczjk/pm;)Ljava/lang/String;
    .locals 1

    const-class v0, Llyiahf/vczjk/lb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lb4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/lb4;->value()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo00o(Llyiahf/vczjk/u34;)Llyiahf/vczjk/ba4;
    .locals 7

    const-class v0, Llyiahf/vczjk/ca4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ca4;

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/ba4;->OooOOO0:Llyiahf/vczjk/ba4;

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/ba4;->OooOOO0:Llyiahf/vczjk/ba4;

    invoke-interface {p1}, Llyiahf/vczjk/ca4;->value()[Ljava/lang/String;

    move-result-object v0

    const/4 v6, 0x0

    if-eqz v0, :cond_3

    array-length v1, v0

    if-nez v1, :cond_1

    goto :goto_2

    :cond_1
    new-instance v1, Ljava/util/HashSet;

    array-length v2, v0

    invoke-direct {v1, v2}, Ljava/util/HashSet;-><init>(I)V

    array-length v2, v0

    move v3, v6

    :goto_0
    if-ge v3, v2, :cond_2

    aget-object v4, v0, v3

    invoke-virtual {v1, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_2
    :goto_1
    move-object v2, v1

    goto :goto_3

    :cond_3
    :goto_2
    sget-object v1, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    goto :goto_1

    :goto_3
    invoke-interface {p1}, Llyiahf/vczjk/ca4;->ignoreUnknown()Z

    move-result v3

    invoke-interface {p1}, Llyiahf/vczjk/ca4;->allowGetters()Z

    move-result v4

    invoke-interface {p1}, Llyiahf/vczjk/ca4;->allowSetters()Z

    move-result v5

    invoke-static {v2, v3, v4, v5, v6}, Llyiahf/vczjk/ba4;->OooO00o(Ljava/util/Set;ZZZZ)Z

    move-result p1

    if-eqz p1, :cond_4

    sget-object p1, Llyiahf/vczjk/ba4;->OooOOO0:Llyiahf/vczjk/ba4;

    return-object p1

    :cond_4
    new-instance v1, Llyiahf/vczjk/ba4;

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/ba4;-><init>(Ljava/util/Set;ZZZZ)V

    return-object v1
.end method

.method public final Oooo0O0(Llyiahf/vczjk/pm;)Ljava/lang/Integer;
    .locals 1

    const-class v0, Llyiahf/vczjk/kb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kb4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/kb4;->index()I

    move-result p1

    const/4 v0, -0x1

    if-eq p1, v0, :cond_0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final Oooo0OO(Llyiahf/vczjk/fc5;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;
    .locals 1

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p3}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result p3

    if-eqz p3, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p1, p2}, Llyiahf/vczjk/r54;->o00o0O(Llyiahf/vczjk/fc5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/e59;

    move-result-object p1

    return-object p1

    :cond_1
    :goto_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final Oooo0o(Llyiahf/vczjk/hm;)Llyiahf/vczjk/xa7;
    .locals 3

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/sb4;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sb4;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/sb4;->namespace()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v2

    if-nez v2, :cond_1

    goto :goto_0

    :cond_1
    move-object v0, v1

    :goto_0
    invoke-interface {p1}, Llyiahf/vczjk/sb4;->value()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v0}, Llyiahf/vczjk/xa7;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo0o0(Llyiahf/vczjk/pm;)Llyiahf/vczjk/xn;
    .locals 2

    const-class v0, Llyiahf/vczjk/ka4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ka4;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/ka4;->value()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/xn;

    const/4 v1, 0x1

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/xn;-><init>(ILjava/lang/String;)V

    return-object v0

    :cond_0
    const-class v0, Llyiahf/vczjk/z84;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z84;

    if-eqz p1, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/z84;->value()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/xn;

    const/4 v1, 0x2

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/xn;-><init>(ILjava/lang/String;)V

    return-object v0

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public final Oooo0oO(Llyiahf/vczjk/pm;)Ljava/lang/Object;
    .locals 2

    const-class v0, Llyiahf/vczjk/xb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xb4;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/xb4;->contentConverter()Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_2

    const-class v1, Llyiahf/vczjk/ep1;

    if-ne p1, v1, :cond_1

    goto :goto_0

    :cond_1
    return-object p1

    :cond_2
    :goto_0
    return-object v0
.end method

.method public final Oooo0oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 2

    const-class v0, Llyiahf/vczjk/xb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xb4;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/xb4;->converter()Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_2

    const-class v1, Llyiahf/vczjk/ep1;

    if-ne p1, v1, :cond_1

    goto :goto_0

    :cond_1
    return-object p1

    :cond_2
    :goto_0
    return-object v0
.end method

.method public final OoooO(Llyiahf/vczjk/pm;)Llyiahf/vczjk/ac4;
    .locals 3

    const-class v0, Llyiahf/vczjk/bc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bc4;

    sget-object v0, Llyiahf/vczjk/ac4;->OooOOO0:Llyiahf/vczjk/ac4;

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/bc4;->nulls()Llyiahf/vczjk/d56;

    move-result-object v1

    invoke-interface {p1}, Llyiahf/vczjk/bc4;->contentNulls()Llyiahf/vczjk/d56;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/d56;->OooOOOo:Llyiahf/vczjk/d56;

    if-nez v1, :cond_1

    move-object v1, v2

    :cond_1
    if-nez p1, :cond_2

    move-object p1, v2

    :cond_2
    if-ne v1, v2, :cond_3

    if-ne p1, v2, :cond_3

    return-object v0

    :cond_3
    new-instance v0, Llyiahf/vczjk/ac4;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/ac4;-><init>(Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    return-object v0
.end method

.method public final OoooO0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/wb4;
    .locals 1

    const-class v0, Llyiahf/vczjk/xb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xb4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/xb4;->typing()Llyiahf/vczjk/wb4;

    move-result-object p1

    return-object p1
.end method

.method public final OoooO00(Llyiahf/vczjk/u34;)Ljava/lang/Boolean;
    .locals 1

    const-class v0, Llyiahf/vczjk/mb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mb4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/mb4;->alphabetic()Z

    move-result p1

    if-eqz p1, :cond_0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OoooO0O(Llyiahf/vczjk/u34;)Ljava/lang/Object;
    .locals 3

    const-class v0, Llyiahf/vczjk/xb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xb4;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/xb4;->using()Ljava/lang/Class;

    move-result-object v0

    const-class v1, Llyiahf/vczjk/yb4;

    if-eq v0, v1, :cond_0

    return-object v0

    :cond_0
    const-class v0, Llyiahf/vczjk/nb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nb4;

    if-eqz v0, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/nb4;->value()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/u34;->OooOoOO()Ljava/lang/Class;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/s46;

    const/4 v1, 0x0

    const/4 v2, 0x2

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/s46;-><init>(IILjava/lang/Class;)V

    return-object v0

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OoooOO0(Llyiahf/vczjk/u34;)Ljava/util/List;
    .locals 6

    const-class v0, Llyiahf/vczjk/ec4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ec4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/ec4;->value()[Llyiahf/vczjk/dc4;

    move-result-object p1

    new-instance v0, Ljava/util/ArrayList;

    array-length v1, p1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    array-length v1, p1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    aget-object v3, p1, v2

    new-instance v4, Llyiahf/vczjk/zt5;

    invoke-interface {v3}, Llyiahf/vczjk/dc4;->value()Ljava/lang/Class;

    move-result-object v5

    invoke-interface {v3}, Llyiahf/vczjk/dc4;->name()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v4, v5, v3}, Llyiahf/vczjk/zt5;-><init>(Ljava/lang/Class;Ljava/lang/String;)V

    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    return-object v0
.end method

.method public final OoooOOO(Llyiahf/vczjk/fc5;Llyiahf/vczjk/hm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;
    .locals 0

    invoke-static {p1, p2}, Llyiahf/vczjk/r54;->o00o0O(Llyiahf/vczjk/fc5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/e59;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/wt5;
    .locals 5

    const-class v0, Llyiahf/vczjk/qc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qc4;

    if-eqz p1, :cond_6

    invoke-interface {p1}, Llyiahf/vczjk/qc4;->enabled()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/qc4;->prefix()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1}, Llyiahf/vczjk/qc4;->suffix()Ljava/lang/String;

    move-result-object p1

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v3

    if-lez v3, :cond_1

    move v3, v2

    goto :goto_0

    :cond_1
    move v3, v1

    :goto_0
    if-eqz p1, :cond_2

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v4

    if-lez v4, :cond_2

    move v1, v2

    :cond_2
    if-eqz v3, :cond_4

    if-eqz v1, :cond_3

    new-instance v1, Llyiahf/vczjk/st5;

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/st5;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    return-object v1

    :cond_3
    new-instance p1, Llyiahf/vczjk/tt5;

    const/4 v1, 0x0

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/tt5;-><init>(Ljava/lang/String;I)V

    return-object p1

    :cond_4
    if-eqz v1, :cond_5

    new-instance v0, Llyiahf/vczjk/tt5;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/tt5;-><init>(Ljava/lang/String;I)V

    return-object v0

    :cond_5
    sget-object p1, Llyiahf/vczjk/wt5;->OooOOO0:Llyiahf/vczjk/vt5;

    return-object p1

    :cond_6
    :goto_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OoooOo0(Llyiahf/vczjk/hm;)Ljava/lang/Object;
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/uc4;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uc4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/uc4;->value()Ljava/lang/Class;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOoO(Llyiahf/vczjk/u34;)[Ljava/lang/Class;
    .locals 1

    const-class v0, Llyiahf/vczjk/xc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xc4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/xc4;->value()[Ljava/lang/Class;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOoo(Llyiahf/vczjk/rm;)Ljava/lang/Boolean;
    .locals 1

    const-class v0, Llyiahf/vczjk/r84;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r84;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/r84;->enabled()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

.method public final Ooooo00(Llyiahf/vczjk/rm;)Z
    .locals 1

    const-class v0, Llyiahf/vczjk/r84;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->o0ooOoO(Ljava/lang/Class;)Z

    move-result p1

    return p1
.end method

.method public final Ooooo0o(Llyiahf/vczjk/pm;)Ljava/lang/Boolean;
    .locals 1

    const-class v0, Llyiahf/vczjk/s84;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/s84;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/s84;->enabled()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

.method public final OooooO0(Llyiahf/vczjk/pm;)Ljava/lang/Boolean;
    .locals 1

    const-class v0, Llyiahf/vczjk/tc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tc4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/tc4;->value()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

.method public final OooooOO(Llyiahf/vczjk/rm;)Z
    .locals 1

    const-class v0, Llyiahf/vczjk/tc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tc4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/tc4;->value()Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooooOo(Llyiahf/vczjk/u34;)Z
    .locals 2

    const-class v0, Llyiahf/vczjk/b94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/b94;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/b94;->mode()Llyiahf/vczjk/a94;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/a94;->OooOOO:Llyiahf/vczjk/a94;

    if-eq p1, v0, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/r54;->_cfgConstructorPropertiesImpliesCreator:Z

    if-eqz v0, :cond_1

    instance-of p1, p1, Llyiahf/vczjk/jm;

    :cond_1
    return v1
.end method

.method public final Oooooo(Llyiahf/vczjk/pm;)Ljava/lang/Boolean;
    .locals 1

    const-class v0, Llyiahf/vczjk/kb4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kb4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/kb4;->required()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final Oooooo0(Llyiahf/vczjk/pm;)Z
    .locals 1

    const-class v0, Llyiahf/vczjk/aa4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/aa4;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/aa4;->value()Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OoooooO(Ljava/lang/annotation/Annotation;)Z
    .locals 2

    invoke-interface {p1}, Ljava/lang/annotation/Annotation;->annotationType()Ljava/lang/Class;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/r54;->OooOOO0:Llyiahf/vczjk/kl4;

    iget-object v0, v0, Llyiahf/vczjk/kl4;->OooOOO:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    if-nez v0, :cond_1

    const-class v0, Llyiahf/vczjk/s54;

    invoke-virtual {p1, v0}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/r54;->OooOOO0:Llyiahf/vczjk/kl4;

    invoke-virtual {v1, v0, p1}, Llyiahf/vczjk/kl4;->OooO0O0(Ljava/io/Serializable;Ljava/lang/Object;)V

    :cond_1
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1
.end method

.method public final Ooooooo(Llyiahf/vczjk/hm;)Ljava/lang/Boolean;
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/da4;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/da4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/da4;->value()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

.method public final o000oOoO(Llyiahf/vczjk/hm;)Ljava/lang/String;
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    const-class v0, Llyiahf/vczjk/oc4;

    invoke-interface {p1, v0}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oc4;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/oc4;->value()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final o00O0O(Llyiahf/vczjk/ec5;Llyiahf/vczjk/u34;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 7

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object p1

    const-class v0, Llyiahf/vczjk/xb4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xb4;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    move-object v2, v1

    goto :goto_0

    :cond_0
    invoke-interface {v0}, Llyiahf/vczjk/xb4;->as()Ljava/lang/Class;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v2

    :goto_0
    const/4 v3, 0x0

    if-eqz v2, :cond_5

    invoke-virtual {p3, v2}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->o0ooOOo()Llyiahf/vczjk/x64;

    move-result-object p3

    goto :goto_2

    :cond_1
    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v4

    :try_start_0
    invoke-virtual {v2, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2, p3}, Llyiahf/vczjk/a4a;->OooO0oo(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object p3

    goto :goto_2

    :cond_2
    invoke-virtual {v4, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-virtual {p1, p3, v2, v3}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object p3

    goto :goto_2

    :cond_3
    invoke-static {v4, v2}, Llyiahf/vczjk/r54;->o00ooo(Ljava/lang/Class;Ljava/lang/Class;)Z

    move-result v4

    if-eqz v4, :cond_4

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->o0ooOOo()Llyiahf/vczjk/x64;

    move-result-object p3

    goto :goto_2

    :catch_0
    move-exception p1

    goto :goto_1

    :cond_4
    new-instance p1, Llyiahf/vczjk/na4;

    const-string v0, "Cannot refine serialization type %s into %s; types not related"

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    filled-new-array {p3, v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v0, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v1, v0}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;)V

    throw p1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    :goto_1
    new-instance v0, Llyiahf/vczjk/na4;

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v3

    filled-new-array {p3, v2, p2, v3}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "Failed to widen type %s with annotation (value %s), from \'%s\': %s"

    invoke-static {p3, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, v1, p2, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_5
    :goto_2
    invoke-virtual {p3}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v2

    if-eqz v2, :cond_b

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v2

    if-nez v0, :cond_6

    move-object v4, v1

    goto :goto_3

    :cond_6
    invoke-interface {v0}, Llyiahf/vczjk/xb4;->keyAs()Ljava/lang/Class;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v4

    :goto_3
    if-eqz v4, :cond_b

    invoke-virtual {v2, v4}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_7

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o0ooOOo()Llyiahf/vczjk/x64;

    move-result-object v2

    goto :goto_4

    :cond_7
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v5

    :try_start_1
    invoke-virtual {v4, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v6

    if-eqz v6, :cond_8

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4, v2}, Llyiahf/vczjk/a4a;->OooO0oo(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v2

    goto :goto_4

    :cond_8
    invoke-virtual {v5, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v6

    if-eqz v6, :cond_9

    invoke-virtual {p1, v2, v4, v3}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object v2

    goto :goto_4

    :cond_9
    invoke-static {v5, v4}, Llyiahf/vczjk/r54;->o00ooo(Ljava/lang/Class;Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_a

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o0ooOOo()Llyiahf/vczjk/x64;

    move-result-object v2
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    :goto_4
    check-cast p3, Llyiahf/vczjk/ub5;

    invoke-virtual {p3, v2}, Llyiahf/vczjk/ub5;->oo0o0Oo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/wb5;

    move-result-object p3

    goto :goto_6

    :catch_1
    move-exception p1

    goto :goto_5

    :cond_a
    :try_start_2
    new-instance p1, Llyiahf/vczjk/na4;

    const-string v0, "Cannot refine serialization key type %s into %s; types not related"

    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    filled-new-array {v2, v3}, [Ljava/lang/Object;

    move-result-object v2

    invoke-static {v0, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v1, v0}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;)V

    throw p1
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_1

    :goto_5
    new-instance v0, Llyiahf/vczjk/na4;

    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v3

    filled-new-array {p3, v2, p2, v3}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "Failed to widen key type of %s with concrete-type annotation (value %s), from \'%s\': %s"

    invoke-static {p3, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, v1, p2, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_b
    :goto_6
    invoke-virtual {p3}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v2

    if-eqz v2, :cond_11

    if-nez v0, :cond_c

    move-object v0, v1

    goto :goto_7

    :cond_c
    invoke-interface {v0}, Llyiahf/vczjk/xb4;->contentAs()Ljava/lang/Class;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v0

    :goto_7
    if-eqz v0, :cond_11

    invoke-virtual {v2, v0}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v4

    if-eqz v4, :cond_d

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o0ooOOo()Llyiahf/vczjk/x64;

    move-result-object p1

    goto :goto_8

    :cond_d
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v4

    :try_start_3
    invoke-virtual {v0, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_e

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v2}, Llyiahf/vczjk/a4a;->OooO0oo(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object p1

    goto :goto_8

    :cond_e
    invoke-virtual {v4, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_f

    invoke-virtual {p1, v2, v0, v3}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object p1

    goto :goto_8

    :cond_f
    invoke-static {v4, v0}, Llyiahf/vczjk/r54;->o00ooo(Ljava/lang/Class;Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_10

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o0ooOOo()Llyiahf/vczjk/x64;

    move-result-object p1
    :try_end_3
    .catch Ljava/lang/IllegalArgumentException; {:try_start_3 .. :try_end_3} :catch_2

    :goto_8
    invoke-virtual {p3, p1}, Llyiahf/vczjk/x64;->oo000o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1

    :catch_2
    move-exception p1

    goto :goto_9

    :cond_10
    :try_start_4
    new-instance p1, Llyiahf/vczjk/na4;

    const-string v3, "Cannot refine serialization content type %s into %s; types not related"

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v4

    filled-new-array {v2, v4}, [Ljava/lang/Object;

    move-result-object v2

    invoke-static {v3, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-direct {p1, v1, v2}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;)V

    throw p1
    :try_end_4
    .catch Ljava/lang/IllegalArgumentException; {:try_start_4 .. :try_end_4} :catch_2

    :goto_9
    new-instance v2, Llyiahf/vczjk/na4;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v3

    filled-new-array {p3, v0, p2, v3}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "Internal error: failed to refine value type of %s with concrete-type annotation (value %s), from \'%s\': %s"

    invoke-static {p3, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {v2, v1, p2, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2

    :cond_11
    return-object p3
.end method

.method public final o00Oo0(Llyiahf/vczjk/rm;Llyiahf/vczjk/rm;)Llyiahf/vczjk/rm;
    .locals 3

    invoke-virtual {p1}, Llyiahf/vczjk/rm;->o000000o()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/rm;->o000000o()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-virtual {v1}, Ljava/lang/Class;->isPrimitive()Z

    move-result v2

    if-nez v2, :cond_1

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Ljava/lang/Class;->isPrimitive()Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_1

    :cond_1
    const-class v2, Ljava/lang/String;

    if-ne v0, v2, :cond_2

    if-eq v1, v2, :cond_3

    :goto_0
    return-object p1

    :cond_2
    if-ne v1, v2, :cond_3

    :goto_1
    return-object p2

    :cond_3
    const/4 p1, 0x0

    return-object p1
.end method

.method public final o0OoOo0(Llyiahf/vczjk/pm;)Ljava/lang/Boolean;
    .locals 1

    const-class v0, Llyiahf/vczjk/ic4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/pm;->o0ooOoO(Ljava/lang/Class;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

.method public final ooOO(Llyiahf/vczjk/t72;Llyiahf/vczjk/u34;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 6

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object p1

    const-class v0, Llyiahf/vczjk/c94;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/u34;->OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/c94;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    move-object v2, v1

    goto :goto_0

    :cond_0
    invoke-interface {v0}, Llyiahf/vczjk/c94;->as()Ljava/lang/Class;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v2

    :goto_0
    const/4 v3, 0x0

    if-eqz v2, :cond_1

    invoke-virtual {p3, v2}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v4

    if-nez v4, :cond_1

    invoke-static {v2, p3}, Llyiahf/vczjk/r54;->oo000o(Ljava/lang/Class;Llyiahf/vczjk/x64;)Z

    move-result v4

    if-nez v4, :cond_1

    :try_start_0
    invoke-virtual {p1, p3, v2, v3}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object p3
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception p1

    new-instance v0, Llyiahf/vczjk/na4;

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v3

    filled-new-array {p3, v2, p2, v3}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "Failed to narrow type %s with annotation (value %s), from \'%s\': %s"

    invoke-static {p3, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, v1, p2, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_1
    :goto_1
    invoke-virtual {p3}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v2

    if-nez v0, :cond_2

    move-object v4, v1

    goto :goto_2

    :cond_2
    invoke-interface {v0}, Llyiahf/vczjk/c94;->keyAs()Ljava/lang/Class;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v4

    :goto_2
    if-eqz v4, :cond_3

    invoke-static {v4, v2}, Llyiahf/vczjk/r54;->oo000o(Ljava/lang/Class;Llyiahf/vczjk/x64;)Z

    move-result v5

    if-nez v5, :cond_3

    :try_start_1
    invoke-virtual {p1, v2, v4, v3}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object v2

    move-object v5, p3

    check-cast v5, Llyiahf/vczjk/ub5;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/ub5;->oo0o0Oo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/wb5;

    move-result-object p3
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_3

    :catch_1
    move-exception p1

    new-instance v0, Llyiahf/vczjk/na4;

    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v3

    filled-new-array {p3, v2, p2, v3}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "Failed to narrow key type of %s with concrete-type annotation (value %s), from \'%s\': %s"

    invoke-static {p3, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, v1, p2, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_3
    :goto_3
    invoke-virtual {p3}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v2

    if-eqz v2, :cond_5

    if-nez v0, :cond_4

    move-object v0, v1

    goto :goto_4

    :cond_4
    invoke-interface {v0}, Llyiahf/vczjk/c94;->contentAs()Ljava/lang/Class;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r54;->o00Ooo(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v0

    :goto_4
    if-eqz v0, :cond_5

    invoke-static {v0, v2}, Llyiahf/vczjk/r54;->oo000o(Ljava/lang/Class;Llyiahf/vczjk/x64;)Z

    move-result v4

    if-nez v4, :cond_5

    :try_start_2
    invoke-virtual {p1, v2, v0, v3}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {p3, p1}, Llyiahf/vczjk/x64;->oo000o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object p1
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_2

    return-object p1

    :catch_2
    move-exception p1

    new-instance v2, Llyiahf/vczjk/na4;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v3

    filled-new-array {p3, v0, p2, v3}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "Failed to narrow value type of %s with concrete-type annotation (value %s), from \'%s\': %s"

    invoke-static {p3, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {v2, v1, p2, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2

    :cond_5
    return-object p3
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/r54;->OooOOO0:Llyiahf/vczjk/kl4;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/kl4;

    const/16 v1, 0x30

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/kl4;-><init>(II)V

    iput-object v0, p0, Llyiahf/vczjk/r54;->OooOOO0:Llyiahf/vczjk/kl4;

    :cond_0
    return-object p0
.end method
