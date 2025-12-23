.class public final Llyiahf/vczjk/c21;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/s1a;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/hl1;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hl1;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/c21;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/c21;->OooOOO:Llyiahf/vczjk/hl1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nk3;Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/c21;->OooOOO:Llyiahf/vczjk/hl1;

    const-class v1, Ljava/lang/Object;

    const/4 v2, 0x2

    const/4 v3, 0x0

    const/4 v4, 0x1

    const/4 v5, 0x0

    iget v6, p0, Llyiahf/vczjk/c21;->OooOOO0:I

    packed-switch v6, :pswitch_data_0

    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    move-result-object v6

    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    move-result-object v7

    const-class v8, Ljava/util/Map;

    invoke-virtual {v8, v7}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v9

    if-nez v9, :cond_0

    goto/16 :goto_3

    :cond_0
    const-class v3, Ljava/util/Properties;

    invoke-virtual {v3, v7}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_1

    new-array v1, v2, [Ljava/lang/reflect/Type;

    const-class v2, Ljava/lang/String;

    aput-object v2, v1, v5

    aput-object v2, v1, v4

    goto :goto_0

    :cond_1
    instance-of v3, v6, Ljava/lang/reflect/WildcardType;

    if-eqz v3, :cond_2

    check-cast v6, Ljava/lang/reflect/WildcardType;

    invoke-interface {v6}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object v3

    aget-object v6, v3, v5

    :cond_2
    invoke-virtual {v8, v7}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    invoke-static {v3}, Llyiahf/vczjk/qqa;->OooOo00(Z)V

    invoke-static {v6, v7, v8}, Llyiahf/vczjk/mc4;->Oooo00o(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    move-result-object v3

    new-instance v8, Ljava/util/HashMap;

    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    invoke-static {v6, v7, v3, v8}, Llyiahf/vczjk/mc4;->OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    move-result-object v3

    instance-of v6, v3, Ljava/lang/reflect/ParameterizedType;

    if-eqz v6, :cond_3

    check-cast v3, Ljava/lang/reflect/ParameterizedType;

    invoke-interface {v3}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object v1

    goto :goto_0

    :cond_3
    new-array v2, v2, [Ljava/lang/reflect/Type;

    aput-object v1, v2, v5

    aput-object v1, v2, v4

    move-object v1, v2

    :goto_0
    aget-object v2, v1, v5

    aget-object v1, v1, v4

    sget-object v3, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    if-eq v2, v3, :cond_5

    const-class v3, Ljava/lang/Boolean;

    if-ne v2, v3, :cond_4

    goto :goto_1

    :cond_4
    invoke-static {v2}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    move-result-object v3

    invoke-virtual {p1, v3}, Llyiahf/vczjk/nk3;->OooO0o0(Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object v3

    goto :goto_2

    :cond_5
    :goto_1
    sget-object v3, Llyiahf/vczjk/x2a;->OooO0OO:Llyiahf/vczjk/r2a;

    :goto_2
    new-instance v4, Llyiahf/vczjk/t1a;

    invoke-direct {v4, p1, v3, v2}, Llyiahf/vczjk/t1a;-><init>(Llyiahf/vczjk/nk3;Llyiahf/vczjk/r1a;Ljava/lang/reflect/Type;)V

    invoke-static {v1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    move-result-object v2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/nk3;->OooO0o0(Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/t1a;

    invoke-direct {v3, p1, v2, v1}, Llyiahf/vczjk/t1a;-><init>(Llyiahf/vczjk/nk3;Llyiahf/vczjk/r1a;Ljava/lang/reflect/Type;)V

    invoke-virtual {v0, p2, v5}, Llyiahf/vczjk/hl1;->OooO0o0(Lcom/google/gson/reflect/TypeToken;Z)Llyiahf/vczjk/m66;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/xb5;

    invoke-direct {p2, p0, v4, v3, p1}, Llyiahf/vczjk/xb5;-><init>(Llyiahf/vczjk/c21;Llyiahf/vczjk/t1a;Llyiahf/vczjk/t1a;Llyiahf/vczjk/m66;)V

    move-object v3, p2

    :goto_3
    return-object v3

    :pswitch_0
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    move-result-object v2

    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    move-result-object v4

    const-class v6, Ljava/util/Collection;

    invoke-virtual {v6, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v7

    if-nez v7, :cond_6

    goto :goto_4

    :cond_6
    instance-of v3, v2, Ljava/lang/reflect/WildcardType;

    if-eqz v3, :cond_7

    check-cast v2, Ljava/lang/reflect/WildcardType;

    invoke-interface {v2}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object v2

    aget-object v2, v2, v5

    :cond_7
    invoke-virtual {v6, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    invoke-static {v3}, Llyiahf/vczjk/qqa;->OooOo00(Z)V

    invoke-static {v2, v4, v6}, Llyiahf/vczjk/mc4;->Oooo00o(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    move-result-object v3

    new-instance v6, Ljava/util/HashMap;

    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    invoke-static {v2, v4, v3, v6}, Llyiahf/vczjk/mc4;->OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    move-result-object v2

    instance-of v3, v2, Ljava/lang/reflect/ParameterizedType;

    if-eqz v3, :cond_8

    check-cast v2, Ljava/lang/reflect/ParameterizedType;

    invoke-interface {v2}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object v1

    aget-object v1, v1, v5

    :cond_8
    invoke-static {v1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    move-result-object v2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/nk3;->OooO0o0(Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/t1a;

    invoke-direct {v3, p1, v2, v1}, Llyiahf/vczjk/t1a;-><init>(Llyiahf/vczjk/nk3;Llyiahf/vczjk/r1a;Ljava/lang/reflect/Type;)V

    invoke-virtual {v0, p2, v5}, Llyiahf/vczjk/hl1;->OooO0o0(Lcom/google/gson/reflect/TypeToken;Z)Llyiahf/vczjk/m66;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/b21;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/b21;-><init>(Llyiahf/vczjk/t1a;Llyiahf/vczjk/m66;)V

    move-object v3, p2

    :goto_4
    return-object v3

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
