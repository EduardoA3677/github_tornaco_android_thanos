.class public final Llyiahf/vczjk/ua0;
.super Llyiahf/vczjk/ya0;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _delegate:Llyiahf/vczjk/ya0;

.field protected final _orderedProperties:[Llyiahf/vczjk/ph8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ya0;[Llyiahf/vczjk/ph8;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/ya0;-><init>(Llyiahf/vczjk/ya0;)V

    iput-object p1, p0, Llyiahf/vczjk/ua0;->_delegate:Llyiahf/vczjk/ya0;

    iput-object p2, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 9

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_f

    iget-boolean v0, p0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    const-string v2, "Unexpected JSON values; expected at most %d properties (in JSON Array)"

    const/4 v3, 0x0

    if-nez v0, :cond_9

    iget-boolean v0, p0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ya0;->OooooOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o000OoO(Ljava/lang/Object;)V

    iget-object v4, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v4, :cond_1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_1
    iget-boolean v4, p0, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    if-eqz v4, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00ooo()Ljava/lang/Class;

    move-result-object v4

    goto :goto_0

    :cond_2
    move-object v4, v1

    :goto_0
    iget-object v5, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    array-length v6, v5

    :goto_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v7, v8, :cond_3

    goto :goto_2

    :cond_3
    if-ne v3, v6, :cond_6

    iget-boolean v3, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    if-eqz v3, :cond_5

    :cond_4
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne p1, v1, :cond_4

    :goto_2
    return-object v0

    :cond_5
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {p1, p0, v8, v2, p2}, Llyiahf/vczjk/v72;->o0000Oo0(Llyiahf/vczjk/e94;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v1

    :cond_6
    aget-object v7, v5, v3

    add-int/lit8 v3, v3, 0x1

    if-eqz v7, :cond_8

    if-eqz v4, :cond_7

    invoke-virtual {v7, v4}, Llyiahf/vczjk/ph8;->OooOoo0(Ljava/lang/Class;)Z

    move-result v8

    if-eqz v8, :cond_8

    :cond_7
    :try_start_0
    invoke-virtual {v7, p2, p1, v0}, Llyiahf/vczjk/ph8;->OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception p2

    invoke-virtual {v7}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-static {p2, v0, v2, p1}, Llyiahf/vczjk/ya0;->o00oO0o(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;)V

    throw v1

    :cond_8
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto :goto_1

    :cond_9
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o000OoO(Ljava/lang/Object;)V

    iget-object v4, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    array-length v5, v4

    :goto_3
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v6, v7, :cond_a

    goto :goto_5

    :cond_a
    if-ne v3, v5, :cond_d

    iget-boolean v3, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    if-nez v3, :cond_c

    sget-object v3, Llyiahf/vczjk/w72;->OooOOo0:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v3

    if-nez v3, :cond_b

    goto :goto_4

    :cond_b
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {p1, p0, v7, v2, p2}, Llyiahf/vczjk/v72;->o0000Oo0(Llyiahf/vczjk/e94;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v1

    :cond_c
    :goto_4
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne p1, v1, :cond_c

    :goto_5
    return-object v0

    :cond_d
    aget-object v6, v4, v3

    if-eqz v6, :cond_e

    :try_start_1
    invoke-virtual {v6, p2, p1, v0}, Llyiahf/vczjk/ph8;->OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_6

    :catch_1
    move-exception p2

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-static {p2, v0, v2, p1}, Llyiahf/vczjk/ya0;->o00oO0o(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;)V

    throw v1

    :cond_e
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    :goto_6
    add-int/lit8 v3, v3, 0x1

    goto :goto_3

    :cond_f
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ua0;->o0ooOO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    throw v1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    invoke-virtual {p1, p3}, Llyiahf/vczjk/eb4;->o000OoO(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p2}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_1

    goto :goto_2

    :cond_1
    if-ne v3, v2, :cond_4

    iget-boolean v0, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    if-nez v0, :cond_3

    sget-object v0, Llyiahf/vczjk/w72;->OooOOo0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_1

    :cond_2
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string p3, "Unexpected JSON values; expected at most %d properties (in JSON Array)"

    invoke-virtual {p2, p0, v5, p3, p1}, Llyiahf/vczjk/v72;->o0000Oo0(Llyiahf/vczjk/e94;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v1

    :cond_3
    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne p2, v0, :cond_3

    :goto_2
    return-object p3

    :cond_4
    aget-object v4, v0, v3

    if-eqz v4, :cond_5

    :try_start_0
    invoke-virtual {v4, p1, p2, p3}, Llyiahf/vczjk/ph8;->OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_3

    :catch_0
    move-exception p1

    invoke-virtual {v4}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, p3, v0, p2}, Llyiahf/vczjk/ya0;->o00oO0o(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;)V

    throw v1

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    :goto_3
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_6
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/ua0;->o0ooOO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    throw v1
.end method

.method public final OooOOOo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/e94;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ua0;->_delegate:Llyiahf/vczjk/ya0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ya0;->OooOOOo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/e94;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    invoke-virtual {v0, p2, p1, v1}, Llyiahf/vczjk/oa7;->OooO0Oo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u66;)Llyiahf/vczjk/lb7;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    array-length v3, v2

    iget-boolean v4, p0, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    const/4 v5, 0x0

    if-eqz v4, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00ooo()Ljava/lang/Class;

    move-result-object v4

    goto :goto_0

    :cond_0
    move-object v4, v5

    :goto_0
    const/4 v6, 0x0

    move-object v7, v5

    :goto_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v8, v9, :cond_9

    if-ge v6, v3, :cond_1

    aget-object v8, v2, v6

    goto :goto_2

    :cond_1
    move-object v8, v5

    :goto_2
    if-nez v8, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto/16 :goto_3

    :cond_2
    if-eqz v4, :cond_3

    invoke-virtual {v8, v4}, Llyiahf/vczjk/ph8;->OooOoo0(Ljava/lang/Class;)Z

    move-result v9

    if-nez v9, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto :goto_3

    :cond_3
    if-eqz v7, :cond_4

    :try_start_0
    invoke-virtual {v8, p2, p1, v7}, Llyiahf/vczjk/ph8;->OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_3

    :catch_0
    move-exception p2

    invoke-virtual {v8}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-static {p2, v7, v0, p1}, Llyiahf/vczjk/ya0;->o00oO0o(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;)V

    throw v5

    :cond_4
    invoke-virtual {v8}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v9

    invoke-virtual {v0, v9}, Llyiahf/vczjk/oa7;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object v10

    if-eqz v10, :cond_6

    invoke-virtual {v10, p1, p2}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v8

    invoke-virtual {v1, v10, v8}, Llyiahf/vczjk/lb7;->OooO0O0(Llyiahf/vczjk/ph8;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_8

    :try_start_1
    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/oa7;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/lb7;)Ljava/lang/Object;

    move-result-object v7
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    invoke-virtual {p2, v7}, Llyiahf/vczjk/eb4;->o000OoO(Ljava/lang/Object;)V

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v8

    iget-object v9, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v9}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v9

    if-ne v8, v9, :cond_5

    goto :goto_3

    :cond_5
    iget-object p2, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "Cannot support implicit polymorphic deserialization for POJOs-as-Arrays style: nominal type "

    const-string v3, ", actual type "

    invoke-static {v2, v0, v3, v1}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v5

    :catch_1
    move-exception p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-static {p2, v0, v9, p1}, Llyiahf/vczjk/ya0;->o00oO0o(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;)V

    throw v5

    :cond_6
    invoke-virtual {v1, v9}, Llyiahf/vczjk/lb7;->OooO0Oo(Ljava/lang/String;)Z

    move-result v9

    if-eqz v9, :cond_7

    goto :goto_3

    :cond_7
    invoke-virtual {v8, p1, p2}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v9

    invoke-virtual {v1, v8, v9}, Llyiahf/vczjk/lb7;->OooO0OO(Llyiahf/vczjk/ph8;Ljava/lang/Object;)V

    :cond_8
    :goto_3
    add-int/lit8 v6, v6, 0x1

    goto/16 :goto_1

    :cond_9
    if-nez v7, :cond_a

    :try_start_2
    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/oa7;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/lb7;)Ljava/lang/Object;

    move-result-object p1
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    return-object p1

    :catch_2
    move-exception p2

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/ya0;->o00oO0O(Ljava/lang/Exception;Llyiahf/vczjk/v72;)V

    throw v5

    :cond_a
    return-object v7
.end method

.method public final OoooOoo()Llyiahf/vczjk/ya0;
    .locals 0

    return-object p0
.end method

.method public final o00Ooo(Llyiahf/vczjk/fb0;)Llyiahf/vczjk/ya0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ua0;

    iget-object v1, p0, Llyiahf/vczjk/ua0;->_delegate:Llyiahf/vczjk/ya0;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ya0;->o00Ooo(Llyiahf/vczjk/fb0;)Llyiahf/vczjk/ya0;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/ua0;-><init>(Llyiahf/vczjk/ya0;[Llyiahf/vczjk/ph8;)V

    return-object v0
.end method

.method public final o00o0O(Ljava/util/Set;)Llyiahf/vczjk/ya0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ua0;

    iget-object v1, p0, Llyiahf/vczjk/ua0;->_delegate:Llyiahf/vczjk/ya0;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ya0;->o00o0O(Ljava/util/Set;)Llyiahf/vczjk/ya0;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/ua0;-><init>(Llyiahf/vczjk/ya0;[Llyiahf/vczjk/ph8;)V

    return-object v0
.end method

.method public final o00ooo()Llyiahf/vczjk/ya0;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ua0;

    iget-object v1, p0, Llyiahf/vczjk/ua0;->_delegate:Llyiahf/vczjk/ya0;

    invoke-virtual {v1}, Llyiahf/vczjk/ya0;->o00ooo()Llyiahf/vczjk/ya0;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ua0;-><init>(Llyiahf/vczjk/ya0;[Llyiahf/vczjk/ph8;)V

    return-object v0
.end method

.method public final o0ooOO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V
    .locals 6

    invoke-virtual {p0, p1}, Llyiahf/vczjk/m49;->OoooOO0(Llyiahf/vczjk/v72;)Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v3

    filled-new-array {v0, v3}, [Ljava/lang/Object;

    move-result-object v5

    const-string v4, "Cannot deserialize a POJO (of type %s) from non-Array representation (token: %s): type/property designed to be serialized as JSON Array"

    move-object v0, p1

    move-object v3, p2

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/v72;->o00000O0(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Llyiahf/vczjk/eb4;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final oo000o(Llyiahf/vczjk/u66;)Llyiahf/vczjk/ya0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ua0;

    iget-object v1, p0, Llyiahf/vczjk/ua0;->_delegate:Llyiahf/vczjk/ya0;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ya0;->oo000o(Llyiahf/vczjk/u66;)Llyiahf/vczjk/ya0;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/ua0;->_orderedProperties:[Llyiahf/vczjk/ph8;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/ua0;-><init>(Llyiahf/vczjk/ya0;[Llyiahf/vczjk/ph8;)V

    return-object v0
.end method
