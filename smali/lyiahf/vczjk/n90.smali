.class public abstract Llyiahf/vczjk/n90;
.super Llyiahf/vczjk/y82;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# instance fields
.field protected final _factoryConfig:Llyiahf/vczjk/z82;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/xa7;

    const/4 v1, 0x0

    const-string v2, "@JsonUnwrapped"

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/xa7;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/z82;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    return-void
.end method

.method public static OooO(Llyiahf/vczjk/qs1;Llyiahf/vczjk/gn;ZZ)V
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/gn;->o000000o()Ljava/lang/Class;

    move-result-object v0

    const-class v1, Ljava/lang/String;

    if-eq v0, v1, :cond_d

    const-class v1, Ljava/lang/CharSequence;

    if-ne v0, v1, :cond_0

    goto :goto_4

    :cond_0
    sget-object v1, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    if-eq v0, v1, :cond_b

    const-class v1, Ljava/lang/Integer;

    if-ne v0, v1, :cond_1

    goto :goto_3

    :cond_1
    sget-object v1, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    if-eq v0, v1, :cond_9

    const-class v1, Ljava/lang/Long;

    if-ne v0, v1, :cond_2

    goto :goto_2

    :cond_2
    sget-object v1, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    if-eq v0, v1, :cond_7

    const-class v1, Ljava/lang/Double;

    if-ne v0, v1, :cond_3

    goto :goto_1

    :cond_3
    sget-object v1, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    if-eq v0, v1, :cond_5

    const-class v1, Ljava/lang/Boolean;

    if-ne v0, v1, :cond_4

    goto :goto_0

    :cond_4
    if-eqz p2, :cond_e

    const/4 p3, 0x0

    const/4 v0, 0x0

    invoke-virtual {p0, p1, p2, p3, v0}, Llyiahf/vczjk/qs1;->OooO0O0(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;I)V

    return-void

    :cond_5
    :goto_0
    if-nez p2, :cond_6

    if-eqz p3, :cond_e

    :cond_6
    const/4 p3, 0x5

    invoke-virtual {p0, p1, p3, p2}, Llyiahf/vczjk/qs1;->OooO0Oo(Llyiahf/vczjk/gn;IZ)Z

    return-void

    :cond_7
    :goto_1
    if-nez p2, :cond_8

    if-eqz p3, :cond_e

    :cond_8
    const/4 p3, 0x4

    invoke-virtual {p0, p1, p3, p2}, Llyiahf/vczjk/qs1;->OooO0Oo(Llyiahf/vczjk/gn;IZ)Z

    return-void

    :cond_9
    :goto_2
    if-nez p2, :cond_a

    if-eqz p3, :cond_e

    :cond_a
    const/4 p3, 0x3

    invoke-virtual {p0, p1, p3, p2}, Llyiahf/vczjk/qs1;->OooO0Oo(Llyiahf/vczjk/gn;IZ)Z

    return-void

    :cond_b
    :goto_3
    if-nez p2, :cond_c

    if-eqz p3, :cond_e

    :cond_c
    const/4 p3, 0x2

    invoke-virtual {p0, p1, p3, p2}, Llyiahf/vczjk/qs1;->OooO0Oo(Llyiahf/vczjk/gn;IZ)Z

    return-void

    :cond_d
    :goto_4
    if-nez p2, :cond_f

    if-eqz p3, :cond_e

    goto :goto_5

    :cond_e
    return-void

    :cond_f
    :goto_5
    const/4 p3, 0x1

    invoke-virtual {p0, p1, p3, p2}, Llyiahf/vczjk/qs1;->OooO0Oo(Llyiahf/vczjk/gn;IZ)Z

    return-void
.end method

.method public static OooO0oO(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;Llyiahf/vczjk/eb0;)Z
    .locals 1

    if-eqz p2, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb0;->OooOoO0()Z

    move-result v0

    if-nez v0, :cond_2

    :cond_0
    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/gn;->o000OOo(I)Llyiahf/vczjk/vm;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/yn;->OooOOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/t54;

    move-result-object p0

    if-eqz p0, :cond_1

    goto :goto_0

    :cond_1
    if-eqz p2, :cond_3

    invoke-interface {p2}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_3

    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    move-result p0

    if-nez p0, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/eb0;->OooO0o()Z

    move-result p0

    if-eqz p0, :cond_3

    :cond_2
    :goto_0
    const/4 p0, 0x1

    return p0

    :cond_3
    return v0
.end method

.method public static OooOO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/gn;)Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object p0

    invoke-virtual {v0, p0, p1}, Llyiahf/vczjk/yn;->OooO0o0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/a94;

    move-result-object p0

    if-eqz p0, :cond_0

    sget-object p1, Llyiahf/vczjk/a94;->OooOOO:Llyiahf/vczjk/a94;

    if-eq p0, p1, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/vm;)V
    .locals 1

    invoke-virtual {p2}, Llyiahf/vczjk/vm;->o0OO00O()I

    move-result p2

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v0, "Cannot define Creator parameter %d as `@JsonUnwrapped`: combination not yet supported"

    invoke-static {v0, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    iget-object p1, p1, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    const/4 p0, 0x0

    throw p0
.end method

.method public static OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/u34;)Llyiahf/vczjk/e94;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yn;->OooOO0(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/v72;->OoooooO(Ljava/lang/Object;)Llyiahf/vczjk/e94;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooOOO0(Ljava/lang/Class;Llyiahf/vczjk/t72;Llyiahf/vczjk/pm;)Llyiahf/vczjk/tp2;
    .locals 12

    if-eqz p2, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/pm;->o0ooOO0()Ljava/lang/reflect/Member;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v1

    invoke-static {v0, v1}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object p1

    invoke-virtual {p0}, Ljava/lang/Class;->getEnumConstants()[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Ljava/lang/Enum;

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    array-length v2, v0

    :cond_1
    :goto_0
    add-int/lit8 v2, v2, -0x1

    if-ltz v2, :cond_2

    aget-object v3, v0, v2

    :try_start_0
    invoke-virtual {p2, v3}, Llyiahf/vczjk/pm;->o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_1

    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v1, v4, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p0

    new-instance p1, Ljava/lang/IllegalArgumentException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "Failed to access @JsonValue of Enum value "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ": "

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    if-eqz p1, :cond_3

    invoke-virtual {p1, p0}, Llyiahf/vczjk/yn;->OooO0oO(Ljava/lang/Class;)Ljava/lang/Enum;

    move-result-object p1

    goto :goto_1

    :cond_3
    const/4 p1, 0x0

    :goto_1
    new-instance p2, Llyiahf/vczjk/tp2;

    invoke-direct {p2, p0, v0, v1, p1}, Llyiahf/vczjk/tp2;-><init>(Ljava/lang/Class;[Ljava/lang/Enum;Ljava/util/HashMap;Ljava/lang/Enum;)V

    return-object p2

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object p1

    invoke-virtual {p0}, Ljava/lang/Class;->getEnumConstants()[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Ljava/lang/Enum;

    if-eqz p2, :cond_9

    array-length v0, p2

    new-array v0, v0, [Ljava/lang/String;

    invoke-virtual {p1, p0, p2, v0}, Llyiahf/vczjk/yn;->OooOO0o(Ljava/lang/Class;[Ljava/lang/Enum;[Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v0

    array-length v1, v0

    new-array v1, v1, [[Ljava/lang/String;

    invoke-virtual {p1, p0, p2, v1}, Llyiahf/vczjk/yn;->OooOO0O(Ljava/lang/Class;[Ljava/lang/Enum;[[Ljava/lang/String;)V

    new-instance v2, Ljava/util/HashMap;

    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    array-length v3, p2

    const/4 v4, 0x0

    move v5, v4

    :goto_2
    if-ge v5, v3, :cond_8

    aget-object v6, p2, v5

    aget-object v7, v0, v5

    if-nez v7, :cond_5

    invoke-virtual {v6}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v7

    :cond_5
    invoke-virtual {v2, v7, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    aget-object v7, v1, v5

    if-eqz v7, :cond_7

    array-length v8, v7

    move v9, v4

    :goto_3
    if-ge v9, v8, :cond_7

    aget-object v10, v7, v9

    invoke-virtual {v2, v10}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v11

    if-nez v11, :cond_6

    invoke-virtual {v2, v10, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_6
    add-int/lit8 v9, v9, 0x1

    goto :goto_3

    :cond_7
    add-int/lit8 v5, v5, 0x1

    goto :goto_2

    :cond_8
    new-instance v0, Llyiahf/vczjk/tp2;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/yn;->OooO0oO(Ljava/lang/Class;)Ljava/lang/Enum;

    move-result-object p1

    invoke-direct {v0, p0, p2, v2, p1}, Llyiahf/vczjk/tp2;-><init>(Ljava/lang/Class;[Ljava/lang/Enum;Ljava/util/HashMap;Ljava/lang/Enum;)V

    return-object v0

    :cond_9
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    const-string p2, "No enum constants for class "

    invoke-virtual {p2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/a21;Llyiahf/vczjk/h90;)Llyiahf/vczjk/e94;
    .locals 14

    move-object/from16 v0, p2

    invoke-virtual {v0}, Llyiahf/vczjk/w11;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v2

    move-object v7, v2

    check-cast v7, Llyiahf/vczjk/e94;

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v9

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/u3a;

    if-nez v2, :cond_0

    invoke-virtual {p0, v9, v1}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object v2

    :cond_0
    iget-object v3, p0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v3}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v4

    if-nez v4, :cond_14

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    const/4 v4, 0x0

    if-nez v7, :cond_1

    const-class v5, Ljava/util/EnumSet;

    invoke-virtual {v5, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_1

    new-instance v3, Llyiahf/vczjk/vp2;

    invoke-direct {v3, v1}, Llyiahf/vczjk/vp2;-><init>(Llyiahf/vczjk/x64;)V

    goto :goto_0

    :cond_1
    move-object v3, v4

    :goto_0
    if-nez v3, :cond_11

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Ooooooo()Z

    move-result v5

    const/4 v6, 0x1

    if-nez v5, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Ooooo0o()Z

    move-result v5

    if-eqz v5, :cond_2

    goto :goto_1

    :cond_2
    move-object/from16 v5, p3

    goto/16 :goto_3

    :cond_3
    :goto_1
    sget-object v5, Llyiahf/vczjk/m90;->OooO00o:Ljava/util/HashMap;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v8

    invoke-virtual {v8}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v5, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Class;

    if-eqz v5, :cond_4

    invoke-virtual {v9}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v8

    invoke-virtual {v8, v0, v5, v6}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/a21;

    move-object v11, v5

    goto :goto_2

    :cond_4
    move-object v11, v4

    :goto_2
    if-nez v11, :cond_6

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v3

    if-eqz v3, :cond_5

    new-instance v3, Llyiahf/vczjk/o000Oo0;

    move-object/from16 v5, p3

    invoke-direct {v3, v5}, Llyiahf/vczjk/o000Oo0;-><init>(Llyiahf/vczjk/h90;)V

    goto :goto_3

    :cond_5
    new-instance p1, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot find a deserializer for non-concrete Collection type "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_6
    invoke-virtual {v9}, Llyiahf/vczjk/ec5;->OooO0oO()Llyiahf/vczjk/jy0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/l90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v9, v11}, Llyiahf/vczjk/l90;->OooO0O0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v0

    if-nez v0, :cond_7

    invoke-static {v9, v11}, Llyiahf/vczjk/l90;->OooO00o(Llyiahf/vczjk/fc5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v0

    if-nez v0, :cond_7

    invoke-static {v9, v11, v9}, Llyiahf/vczjk/l90;->OooO0OO(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/ec5;)Llyiahf/vczjk/hm;

    move-result-object v12

    new-instance v8, Llyiahf/vczjk/yg6;

    const-string v13, "set"

    const/4 v10, 0x0

    invoke-direct/range {v8 .. v13}, Llyiahf/vczjk/yg6;-><init>(Llyiahf/vczjk/fc5;ZLlyiahf/vczjk/x64;Llyiahf/vczjk/hm;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/h90;

    invoke-direct {v0, v8}, Llyiahf/vczjk/h90;-><init>(Llyiahf/vczjk/yg6;)V

    :cond_7
    move-object v5, v0

    move-object v0, v11

    :goto_3
    if-nez v3, :cond_11

    invoke-virtual {p0, v5, p1}, Llyiahf/vczjk/n90;->OooOOOO(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/nca;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/nca;->OooO()Z

    move-result p1

    if-nez p1, :cond_f

    const-class p1, Ljava/util/concurrent/ArrayBlockingQueue;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_8

    new-instance p1, Llyiahf/vczjk/vx;

    invoke-direct {p1, v0, v7, v2, v5}, Llyiahf/vczjk/u11;-><init>(Llyiahf/vczjk/a21;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;)V

    return-object p1

    :cond_8
    sget-object p1, Llyiahf/vczjk/k74;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    const-class v3, Ljava/util/List;

    if-eqz p1, :cond_9

    new-instance p1, Llyiahf/vczjk/j74;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v3

    const/4 v4, 0x7

    invoke-direct {p1, v4, v3}, Llyiahf/vczjk/j74;-><init>(ILlyiahf/vczjk/x64;)V

    goto :goto_5

    :cond_9
    sget-object p1, Llyiahf/vczjk/k74;->OooO0OO:Ljava/lang/Class;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_a

    new-instance p1, Llyiahf/vczjk/j74;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v3

    const/4 v4, 0x2

    invoke-direct {p1, v4, v3}, Llyiahf/vczjk/j74;-><init>(ILlyiahf/vczjk/x64;)V

    goto :goto_5

    :cond_a
    sget-object p1, Llyiahf/vczjk/k74;->OooO0O0:Ljava/lang/Class;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    const-class v8, Ljava/util/Set;

    if-eqz p1, :cond_b

    new-instance p1, Llyiahf/vczjk/j74;

    invoke-virtual {v0, v8}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v3

    invoke-direct {p1, v6, v3}, Llyiahf/vczjk/j74;-><init>(ILlyiahf/vczjk/x64;)V

    goto :goto_5

    :cond_b
    sget-object p1, Llyiahf/vczjk/k74;->OooO0o:Ljava/lang/Class;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    if-nez p1, :cond_d

    sget-object p1, Llyiahf/vczjk/k74;->OooO0oO:Ljava/lang/Class;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_c

    goto :goto_4

    :cond_c
    sget-object p1, Llyiahf/vczjk/k74;->OooO0o0:Ljava/lang/Class;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_e

    new-instance p1, Llyiahf/vczjk/j74;

    invoke-virtual {v0, v8}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v3

    const/4 v4, 0x4

    invoke-direct {p1, v4, v3}, Llyiahf/vczjk/j74;-><init>(ILlyiahf/vczjk/x64;)V

    goto :goto_5

    :cond_d
    :goto_4
    new-instance p1, Llyiahf/vczjk/j74;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v3

    const/4 v4, 0x5

    invoke-direct {p1, v4, v3}, Llyiahf/vczjk/j74;-><init>(ILlyiahf/vczjk/x64;)V

    :goto_5
    new-instance v4, Llyiahf/vczjk/k49;

    invoke-direct {v4, p1}, Llyiahf/vczjk/k49;-><init>(Llyiahf/vczjk/j74;)V

    :cond_e
    if-eqz v4, :cond_f

    return-object v4

    :cond_f
    const-class p1, Ljava/lang/String;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_10

    new-instance v3, Llyiahf/vczjk/m69;

    const/4 v6, 0x0

    const/4 v9, 0x0

    move-object v8, v7

    move-object v4, v0

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/m69;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/nca;Llyiahf/vczjk/e94;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    goto :goto_6

    :cond_10
    move-object v4, v0

    new-instance v3, Llyiahf/vczjk/u11;

    invoke-direct {v3, v4, v7, v2, v5}, Llyiahf/vczjk/u11;-><init>(Llyiahf/vczjk/a21;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;)V

    :cond_11
    :goto_6
    iget-object p1, p0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {p1}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result p1

    if-eqz p1, :cond_13

    iget-object p1, p0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {p1}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v0

    if-nez v0, :cond_12

    goto :goto_7

    :cond_12
    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_13
    :goto_7
    return-object v3

    :cond_14
    invoke-static {v3}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;
    .locals 5

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ec5;->OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/h90;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v1, p1, v0, p2}, Llyiahf/vczjk/yn;->OoooOOO(Llyiahf/vczjk/fc5;Llyiahf/vczjk/hm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;

    move-result-object v1

    const/4 v2, 0x0

    if-nez v1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooOO0()Llyiahf/vczjk/b5a;

    move-result-object v1

    if-nez v1, :cond_0

    return-object v2

    :cond_0
    move-object v0, v2

    goto :goto_0

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/fc5;->OooOooo()Llyiahf/vczjk/k99;

    move-result-object v3

    invoke-virtual {v3, p1, v0}, Llyiahf/vczjk/k99;->OooO0OO(Llyiahf/vczjk/t72;Llyiahf/vczjk/hm;)Ljava/util/ArrayList;

    move-result-object v0

    :goto_0
    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/e59;

    iget-object v4, v3, Llyiahf/vczjk/e59;->OooO0o0:Ljava/lang/Class;

    if-nez v4, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->Ooooo0o()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-virtual {p0, p2}, Llyiahf/vczjk/n90;->OooO0OO(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {p2, v4}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v4

    if-nez v4, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    iput-object v1, v3, Llyiahf/vczjk/e59;->OooO0o0:Ljava/lang/Class;

    move-object v1, v3

    :cond_2
    :try_start_0
    check-cast v1, Llyiahf/vczjk/e59;

    invoke-virtual {v1, p1, p2, v0}, Llyiahf/vczjk/e59;->OooO00o(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;Ljava/util/ArrayList;)Llyiahf/vczjk/v3a;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/d44;

    invoke-direct {v1, v2, v0, p2}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    invoke-virtual {v1, p1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    throw v1
.end method

.method public final OooO0OO(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO00o()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_1
    :goto_0
    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V
    .locals 14

    move-object/from16 v0, p3

    move-object/from16 v1, p4

    const/4 v2, 0x0

    const/4 v3, 0x1

    iget-object v4, v1, Llyiahf/vczjk/ps1;->OooO0Oo:[Llyiahf/vczjk/uqa;

    iget v5, v1, Llyiahf/vczjk/ps1;->OooO0OO:I

    if-eq v3, v5, :cond_4

    const/4 v6, -0x1

    move v7, v6

    :goto_0
    if-ge v2, v5, :cond_2

    aget-object v8, v4, v2

    iget-object v8, v8, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/t54;

    if-nez v8, :cond_1

    if-ltz v7, :cond_0

    goto :goto_1

    :cond_0
    move v7, v2

    :cond_1
    add-int/2addr v2, v3

    goto :goto_0

    :cond_2
    move v6, v7

    :goto_1
    if-ltz v6, :cond_3

    invoke-virtual {v1, v6}, Llyiahf/vczjk/ps1;->OooO0O0(I)Llyiahf/vczjk/xa7;

    move-result-object v2

    if-nez v2, :cond_3

    invoke-virtual/range {p0 .. p4}, Llyiahf/vczjk/n90;->OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V

    return-void

    :cond_3
    invoke-virtual/range {p0 .. p4}, Llyiahf/vczjk/n90;->OooO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V

    return-void

    :cond_4
    aget-object v5, v4, v2

    iget-object v6, v5, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    move-object v12, v6

    check-cast v12, Llyiahf/vczjk/vm;

    iget-object v6, v5, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    move-object v13, v6

    check-cast v13, Llyiahf/vczjk/t54;

    iget-object v5, v5, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/eb0;

    const/4 v6, 0x0

    if-eqz v5, :cond_5

    invoke-virtual {v5}, Llyiahf/vczjk/eb0;->OooOoO0()Z

    move-result v7

    if-eqz v7, :cond_5

    invoke-virtual {v5}, Llyiahf/vczjk/eb0;->getFullName()Llyiahf/vczjk/xa7;

    move-result-object v5

    goto :goto_2

    :cond_5
    move-object v5, v6

    :goto_2
    aget-object v4, v4, v2

    iget-object v4, v4, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/eb0;

    if-nez v5, :cond_7

    if-eqz v13, :cond_6

    goto :goto_3

    :cond_6
    move v7, v2

    goto :goto_4

    :cond_7
    :goto_3
    move v7, v3

    :goto_4
    if-nez v7, :cond_9

    if-eqz v4, :cond_9

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ps1;->OooO0O0(I)Llyiahf/vczjk/xa7;

    move-result-object v5

    if-eqz v5, :cond_8

    invoke-virtual {v4}, Llyiahf/vczjk/eb0;->OooO0o()Z

    move-result v7

    if-eqz v7, :cond_8

    move v7, v3

    goto :goto_5

    :cond_8
    move v7, v2

    :cond_9
    :goto_5
    move-object v10, v5

    iget-object v1, v1, Llyiahf/vczjk/ps1;->OooO0O0:Llyiahf/vczjk/gn;

    if-eqz v7, :cond_a

    const/4 v11, 0x0

    move-object v7, p0

    move-object v8, p1

    move-object/from16 v9, p2

    invoke-virtual/range {v7 .. v13}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object p1

    new-array v4, v3, [Llyiahf/vczjk/ph8;

    aput-object p1, v4, v2

    invoke-virtual {v0, v1, v3, v4}, Llyiahf/vczjk/qs1;->OooO0OO(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;)V

    return-void

    :cond_a
    invoke-static {v0, v1, v3, v3}, Llyiahf/vczjk/n90;->OooO(Llyiahf/vczjk/qs1;Llyiahf/vczjk/gn;ZZ)V

    if-eqz v4, :cond_b

    check-cast v4, Llyiahf/vczjk/eh6;

    iput-object v6, v4, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    :cond_b
    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V
    .locals 10

    iget v0, p4, Llyiahf/vczjk/ps1;->OooO0OO:I

    new-array v1, v0, [Llyiahf/vczjk/ph8;

    const/4 v2, 0x0

    move v7, v2

    :goto_0
    if-ge v7, v0, :cond_3

    iget-object v2, p4, Llyiahf/vczjk/ps1;->OooO0Oo:[Llyiahf/vczjk/uqa;

    aget-object v3, v2, v7

    iget-object v4, v3, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    move-object v9, v4

    check-cast v9, Llyiahf/vczjk/t54;

    iget-object v3, v3, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    move-object v8, v3

    check-cast v8, Llyiahf/vczjk/vm;

    invoke-virtual {p4, v7}, Llyiahf/vczjk/ps1;->OooO0O0(I)Llyiahf/vczjk/xa7;

    move-result-object v3

    if-nez v3, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v3

    invoke-virtual {v3, v8}, Llyiahf/vczjk/yn;->OoooOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/wt5;

    move-result-object v3

    const/4 v4, 0x0

    if-nez v3, :cond_1

    aget-object v2, v2, v7

    iget-object v2, v2, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/vm;

    iget-object v3, p4, Llyiahf/vczjk/ps1;->OooO00o:Llyiahf/vczjk/yn;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/yn;->OooOOOO(Llyiahf/vczjk/pm;)V

    if-eqz v9, :cond_0

    move-object v6, v4

    move-object v3, p0

    move-object v5, p2

    move-object v4, p1

    goto :goto_1

    :cond_0
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p3

    filled-new-array {p3, p4}, [Ljava/lang/Object;

    move-result-object p3

    const-string p4, "Argument #%d has no property name, is not Injectable: can not use as Creator %s"

    invoke-virtual {p1, p2, p4, p3}, Llyiahf/vczjk/v72;->o000OO(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v4

    :cond_1
    invoke-static {p1, p2, v8}, Llyiahf/vczjk/n90;->OooOO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/vm;)V

    throw v4

    :cond_2
    move-object v6, v3

    move-object v4, p1

    move-object v5, p2

    move-object v3, p0

    :goto_1
    invoke-virtual/range {v3 .. v9}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object p1

    aput-object p1, v1, v7

    add-int/lit8 v7, v7, 0x1

    move-object p1, v4

    move-object p2, v5

    goto :goto_0

    :cond_3
    iget-object p1, p4, Llyiahf/vczjk/ps1;->OooO0O0:Llyiahf/vczjk/gn;

    const/4 p2, 0x1

    invoke-virtual {p3, p1, p2, v1}, Llyiahf/vczjk/qs1;->OooO0OO(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;)V

    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V
    .locals 11

    iget v0, p4, Llyiahf/vczjk/ps1;->OooO0OO:I

    new-array v1, v0, [Llyiahf/vczjk/ph8;

    const/4 v2, 0x0

    const/4 v3, -0x1

    move v8, v2

    :goto_0
    const/4 v4, 0x0

    iget-object v5, p4, Llyiahf/vczjk/ps1;->OooO0Oo:[Llyiahf/vczjk/uqa;

    if-ge v8, v0, :cond_2

    aget-object v5, v5, v8

    iget-object v6, v5, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    move-object v9, v6

    check-cast v9, Llyiahf/vczjk/vm;

    iget-object v5, v5, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    move-object v10, v5

    check-cast v10, Llyiahf/vczjk/t54;

    if-eqz v10, :cond_0

    const/4 v7, 0x0

    move-object v4, p0

    move-object v5, p1

    move-object v6, p2

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object p1

    move-object p2, v5

    aput-object p1, v1, v8

    goto :goto_1

    :cond_0
    move-object v6, p2

    move-object p2, p1

    if-gez v3, :cond_1

    move v3, v8

    :goto_1
    add-int/lit8 v8, v8, 0x1

    move-object p1, p2

    move-object p2, v6

    goto :goto_0

    :cond_1
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p3

    filled-new-array {p1, p3, p4}, [Ljava/lang/Object;

    move-result-object p1

    const-string p3, "More than one argument (#%d and #%d) left as delegating for Creator %s: only one allowed"

    invoke-virtual {p2, v6, p3, p1}, Llyiahf/vczjk/v72;->o000OO(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v4

    :cond_2
    move-object v6, p2

    move-object p2, p1

    if-ltz v3, :cond_5

    const/4 p1, 0x1

    iget-object p2, p4, Llyiahf/vczjk/ps1;->OooO0O0:Llyiahf/vczjk/gn;

    if-ne v0, p1, :cond_4

    invoke-static {p3, p2, p1, p1}, Llyiahf/vczjk/n90;->OooO(Llyiahf/vczjk/qs1;Llyiahf/vczjk/gn;ZZ)V

    aget-object p1, v5, v2

    iget-object p1, p1, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/eb0;

    if-eqz p1, :cond_3

    check-cast p1, Llyiahf/vczjk/eh6;

    iput-object v4, p1, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    :cond_3
    return-void

    :cond_4
    invoke-virtual {p3, p2, p1, v1, v3}, Llyiahf/vczjk/qs1;->OooO0O0(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;I)V

    return-void

    :cond_5
    const-string p1, "No argument left as delegating for Creator %s: exactly one required"

    filled-new-array {p4}, [Ljava/lang/Object;

    move-result-object p3

    invoke-virtual {p2, v6, p1, p3}, Llyiahf/vczjk/v72;->o000OO(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v4
.end method

.method public final OooO0oo(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/f59;
    .locals 32

    move-object/from16 v0, p0

    move-object/from16 v2, p1

    move-object/from16 v1, p2

    new-instance v9, Llyiahf/vczjk/qs1;

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v3

    invoke-direct {v9, v2, v3}, Llyiahf/vczjk/qs1;-><init>(Llyiahf/vczjk/h90;Llyiahf/vczjk/t72;)V

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v10

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/h90;->OooO0oO()Ljava/lang/Class;

    move-result-object v4

    iget-object v11, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v3, v4, v11}, Llyiahf/vczjk/fc5;->OooOoo(Ljava/lang/Class;Llyiahf/vczjk/hm;)Llyiahf/vczjk/gka;

    move-result-object v12

    sget-object v3, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    invoke-virtual {v2}, Llyiahf/vczjk/h90;->OooO0O0()Ljava/util/List;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    move-object v13, v3

    :cond_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    const/4 v14, 0x0

    if-eqz v3, :cond_4

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/eb0;

    invoke-virtual {v3}, Llyiahf/vczjk/eb0;->OooOOO0()Ljava/util/Iterator;

    move-result-object v5

    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_0

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/vm;

    invoke-virtual {v6}, Llyiahf/vczjk/vm;->oo0o0Oo()Llyiahf/vczjk/gn;

    move-result-object v15

    invoke-interface {v13, v15}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v16

    check-cast v16, [Llyiahf/vczjk/eb0;

    invoke-virtual {v6}, Llyiahf/vczjk/vm;->o0OO00O()I

    move-result v6

    if-nez v16, :cond_2

    invoke-interface {v13}, Ljava/util/Map;->isEmpty()Z

    move-result v16

    if-eqz v16, :cond_1

    new-instance v13, Ljava/util/LinkedHashMap;

    invoke-direct {v13}, Ljava/util/LinkedHashMap;-><init>()V

    :cond_1
    const/16 v17, 0x0

    invoke-virtual {v15}, Llyiahf/vczjk/gn;->o000000()I

    move-result v7

    new-array v7, v7, [Llyiahf/vczjk/eb0;

    invoke-interface {v13, v15, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-object/from16 v16, v7

    goto :goto_1

    :cond_2
    const/16 v17, 0x0

    aget-object v7, v16, v6

    if-nez v7, :cond_3

    :goto_1
    aput-object v3, v16, v6

    goto :goto_0

    :cond_3
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    aget-object v5, v16, v6

    filled-new-array {v4, v15, v5, v3}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "Conflict: parameter #%d of %s bound to more than one property; %s vs %s"

    invoke-virtual {v1, v2, v4, v3}, Llyiahf/vczjk/v72;->o000OO(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v14

    :cond_4
    const/16 v17, 0x0

    new-instance v3, Ljava/util/LinkedList;

    invoke-direct {v3}, Ljava/util/LinkedList;-><init>()V

    invoke-virtual {v2}, Llyiahf/vczjk/h90;->OooO0oo()Ljava/util/List;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    move/from16 v5, v17

    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    sget-object v7, Llyiahf/vczjk/a94;->OooOOO:Llyiahf/vczjk/a94;

    iget-boolean v15, v9, Llyiahf/vczjk/qs1;->OooO0OO:Z

    iget-boolean v14, v9, Llyiahf/vczjk/qs1;->OooO0O0:Z

    iget-object v8, v9, Llyiahf/vczjk/qs1;->OooO0Oo:[Llyiahf/vczjk/gn;

    move-object/from16 v19, v8

    if-eqz v6, :cond_c

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/rm;

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v8

    invoke-virtual {v10, v8, v6}, Llyiahf/vczjk/yn;->OooO0o0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/a94;

    move-result-object v8

    move-object/from16 v21, v4

    invoke-virtual {v6}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v4

    array-length v4, v4

    if-nez v8, :cond_5

    move/from16 v22, v5

    const/4 v5, 0x1

    if-ne v4, v5, :cond_8

    move-object v4, v12

    check-cast v4, Llyiahf/vczjk/fka;

    invoke-virtual {v4, v6}, Llyiahf/vczjk/fka;->OooO00o(Llyiahf/vczjk/gn;)Z

    move-result v4

    if-eqz v4, :cond_8

    const/4 v4, 0x0

    invoke-static {v10, v6, v4}, Llyiahf/vczjk/ps1;->OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;

    move-result-object v5

    invoke-virtual {v3, v5}, Ljava/util/LinkedList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_5
    move/from16 v22, v5

    if-ne v8, v7, :cond_6

    goto :goto_3

    :cond_6
    if-nez v4, :cond_9

    if-eqz v14, :cond_7

    invoke-virtual {v6}, Llyiahf/vczjk/rm;->OooOo0()Ljava/lang/reflect/AnnotatedElement;

    move-result-object v4

    check-cast v4, Ljava/lang/reflect/Member;

    invoke-static {v4, v15}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_7
    aput-object v6, v19, v17

    :cond_8
    :goto_3
    move-object/from16 v4, v21

    move/from16 v5, v22

    :goto_4
    const/4 v14, 0x0

    goto :goto_2

    :cond_9
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    move-result v4

    const/4 v5, 0x1

    if-eq v4, v5, :cond_b

    const/4 v5, 0x2

    if-eq v4, v5, :cond_a

    invoke-interface {v13, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, [Llyiahf/vczjk/eb0;

    invoke-static {v10, v6, v4}, Llyiahf/vczjk/ps1;->OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;

    move-result-object v4

    invoke-virtual {v0, v1, v2, v9, v4}, Llyiahf/vczjk/n90;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V

    :goto_5
    const/16 v18, 0x1

    goto :goto_6

    :cond_a
    invoke-interface {v13, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, [Llyiahf/vczjk/eb0;

    invoke-static {v10, v6, v4}, Llyiahf/vczjk/ps1;->OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;

    move-result-object v4

    invoke-virtual {v0, v1, v2, v9, v4}, Llyiahf/vczjk/n90;->OooO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V

    goto :goto_5

    :cond_b
    const/4 v4, 0x0

    invoke-static {v10, v6, v4}, Llyiahf/vczjk/ps1;->OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;

    move-result-object v5

    invoke-virtual {v0, v1, v2, v9, v5}, Llyiahf/vczjk/n90;->OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V

    goto :goto_5

    :goto_6
    add-int/lit8 v5, v22, 0x1

    move-object/from16 v4, v21

    goto :goto_4

    :cond_c
    move/from16 v22, v5

    if-lez v22, :cond_e

    :cond_d
    move-object/from16 v26, v12

    move/from16 v27, v14

    goto/16 :goto_f

    :cond_e
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v8

    :goto_7
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_d

    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ps1;

    iget v4, v3, Llyiahf/vczjk/ps1;->OooO0OO:I

    iget-object v5, v3, Llyiahf/vczjk/ps1;->OooO0O0:Llyiahf/vczjk/gn;

    invoke-interface {v13, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    move-object/from16 v21, v6

    check-cast v21, [Llyiahf/vczjk/eb0;

    const/4 v6, 0x1

    if-eq v4, v6, :cond_f

    goto :goto_7

    :cond_f
    iget-object v3, v3, Llyiahf/vczjk/ps1;->OooO0Oo:[Llyiahf/vczjk/uqa;

    aget-object v3, v3, v17

    iget-object v3, v3, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/eb0;

    invoke-static {v10, v5, v3}, Llyiahf/vczjk/n90;->OooO0oO(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;Llyiahf/vczjk/eb0;)Z

    move-result v6

    if-nez v6, :cond_11

    move-object v4, v12

    check-cast v4, Llyiahf/vczjk/fka;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/fka;->OooO00o(Llyiahf/vczjk/gn;)Z

    move-result v4

    move/from16 v6, v17

    invoke-static {v9, v5, v6, v4}, Llyiahf/vczjk/n90;->OooO(Llyiahf/vczjk/qs1;Llyiahf/vczjk/gn;ZZ)V

    if-eqz v3, :cond_10

    check-cast v3, Llyiahf/vczjk/eh6;

    const/4 v4, 0x0

    iput-object v4, v3, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    :cond_10
    :goto_8
    const/16 v17, 0x0

    goto :goto_7

    :cond_11
    new-array v3, v4, [Llyiahf/vczjk/ph8;

    const/4 v6, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    :goto_9
    if-ge v6, v4, :cond_18

    move-object v0, v5

    invoke-virtual {v0, v6}, Llyiahf/vczjk/gn;->o000OOo(I)Llyiahf/vczjk/vm;

    move-result-object v5

    if-nez v21, :cond_12

    const/16 v25, 0x0

    :goto_a
    move/from16 v26, v4

    move v4, v6

    goto :goto_b

    :cond_12
    aget-object v25, v21, v6

    goto :goto_a

    :goto_b
    invoke-virtual {v10, v5}, Llyiahf/vczjk/yn;->OooOOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/t54;

    move-result-object v6

    if-nez v25, :cond_13

    const/16 v27, 0x0

    goto :goto_c

    :cond_13
    invoke-virtual/range {v25 .. v25}, Llyiahf/vczjk/eb0;->getFullName()Llyiahf/vczjk/xa7;

    move-result-object v27

    :goto_c
    if-eqz v25, :cond_14

    invoke-virtual/range {v25 .. v25}, Llyiahf/vczjk/eb0;->OooOoO0()Z

    move-result v25

    if-eqz v25, :cond_14

    const/16 v18, 0x1

    add-int/lit8 v23, v23, 0x1

    move/from16 v25, v14

    move-object v14, v3

    move-object/from16 v3, v27

    move/from16 v27, v25

    move-object/from16 v25, v8

    move/from16 v8, v26

    move-object/from16 v26, v12

    move-object v12, v0

    move-object/from16 v0, p0

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object v3

    aput-object v3, v14, v4

    move-object/from16 v2, p1

    move-object/from16 v1, p2

    goto :goto_d

    :cond_14
    move/from16 v18, v14

    move-object v14, v3

    move-object/from16 v3, v27

    move/from16 v27, v18

    move-object/from16 v25, v8

    move/from16 v8, v26

    const/16 v18, 0x1

    move-object/from16 v26, v12

    move-object v12, v0

    if-eqz v6, :cond_15

    add-int/lit8 v24, v24, 0x1

    move-object/from16 v0, p0

    move-object/from16 v2, p1

    move-object/from16 v1, p2

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object v3

    aput-object v3, v14, v4

    goto :goto_d

    :cond_15
    move-object/from16 v0, p0

    move-object/from16 v2, p1

    move-object/from16 v1, p2

    invoke-virtual {v10, v5}, Llyiahf/vczjk/yn;->OoooOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/wt5;

    move-result-object v3

    if-nez v3, :cond_17

    if-nez v22, :cond_16

    move-object/from16 v22, v5

    :cond_16
    :goto_d
    add-int/lit8 v6, v4, 0x1

    move v4, v8

    move-object v5, v12

    move-object v3, v14

    move-object/from16 v8, v25

    move-object/from16 v12, v26

    move/from16 v14, v27

    goto/16 :goto_9

    :cond_17
    invoke-static {v1, v2, v5}, Llyiahf/vczjk/n90;->OooOO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/vm;)V

    const/16 v16, 0x0

    throw v16

    :cond_18
    move-object/from16 v25, v8

    move-object/from16 v26, v12

    move/from16 v27, v14

    move-object v14, v3

    move v8, v4

    move-object v12, v5

    if-gtz v23, :cond_19

    if-lez v24, :cond_1b

    :cond_19
    add-int v3, v23, v24

    if-ne v3, v8, :cond_1a

    const/4 v6, 0x0

    invoke-virtual {v9, v12, v6, v14}, Llyiahf/vczjk/qs1;->OooO0OO(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;)V

    goto :goto_e

    :cond_1a
    const/4 v6, 0x0

    if-nez v23, :cond_1c

    const/16 v18, 0x1

    add-int/lit8 v3, v24, 0x1

    if-ne v3, v8, :cond_1c

    invoke-virtual {v9, v12, v6, v14, v6}, Llyiahf/vczjk/qs1;->OooO0O0(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;I)V

    :cond_1b
    :goto_e
    move-object/from16 v8, v25

    move-object/from16 v12, v26

    move/from16 v14, v27

    goto/16 :goto_8

    :cond_1c
    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/vm;->o0OO00O()I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    filled-new-array {v3, v12}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "Argument #%d of factory method %s has no property name annotation; must have name when multiple-parameter constructor annotated as Creator"

    invoke-virtual {v1, v2, v4, v3}, Llyiahf/vczjk/v72;->o000OO(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    const/16 v16, 0x0

    throw v16

    :goto_f
    iget-object v3, v2, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OooooOO()Z

    move-result v3

    if-eqz v3, :cond_47

    iget-object v3, v11, Llyiahf/vczjk/hm;->Oooo00o:Ljava/lang/Boolean;

    if-nez v3, :cond_1f

    sget-object v3, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    iget-object v3, v11, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    invoke-virtual {v3}, Ljava/lang/Class;->getModifiers()I

    move-result v4

    invoke-static {v4}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v4

    if-nez v4, :cond_1e

    invoke-static {v3}, Llyiahf/vczjk/vy0;->OooOo00(Ljava/lang/Class;)Z

    move-result v4

    if-eqz v4, :cond_1d

    const/4 v3, 0x0

    goto :goto_10

    :cond_1d
    invoke-virtual {v3}, Ljava/lang/Class;->getEnclosingClass()Ljava/lang/Class;

    move-result-object v3

    :goto_10
    if-eqz v3, :cond_1e

    const/4 v3, 0x1

    goto :goto_11

    :cond_1e
    const/4 v3, 0x0

    :goto_11
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    iput-object v3, v11, Llyiahf/vczjk/hm;->Oooo00o:Ljava/lang/Boolean;

    :cond_1f
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    if-eqz v3, :cond_20

    goto/16 :goto_22

    :cond_20
    invoke-virtual {v11}, Llyiahf/vczjk/hm;->oo000o()Llyiahf/vczjk/uqa;

    move-result-object v3

    iget-object v3, v3, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jm;

    if-eqz v3, :cond_23

    const/16 v17, 0x0

    aget-object v4, v19, v17

    if-eqz v4, :cond_21

    invoke-static {v1, v3}, Llyiahf/vczjk/n90;->OooOO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/gn;)Z

    move-result v4

    if-eqz v4, :cond_23

    :cond_21
    if-eqz v27, :cond_22

    invoke-virtual {v3}, Llyiahf/vczjk/jm;->OooOo0()Ljava/lang/reflect/AnnotatedElement;

    move-result-object v4

    check-cast v4, Ljava/lang/reflect/Member;

    invoke-static {v4, v15}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_22
    const/16 v17, 0x0

    aput-object v3, v19, v17

    :cond_23
    new-instance v3, Ljava/util/LinkedList;

    invoke-direct {v3}, Ljava/util/LinkedList;-><init>()V

    invoke-virtual {v11}, Llyiahf/vczjk/hm;->oo000o()Llyiahf/vczjk/uqa;

    move-result-object v4

    iget-object v4, v4, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    const/4 v5, 0x0

    :cond_24
    :goto_12
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_29

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/jm;

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v11

    invoke-virtual {v10, v11, v6}, Llyiahf/vczjk/yn;->OooO0o0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/a94;

    move-result-object v11

    if-ne v7, v11, :cond_25

    goto :goto_12

    :cond_25
    if-nez v11, :cond_26

    move-object/from16 v11, v26

    check-cast v11, Llyiahf/vczjk/fka;

    invoke-virtual {v11, v6}, Llyiahf/vczjk/fka;->OooO00o(Llyiahf/vczjk/gn;)Z

    move-result v11

    if-eqz v11, :cond_24

    invoke-interface {v13, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, [Llyiahf/vczjk/eb0;

    invoke-static {v10, v6, v11}, Llyiahf/vczjk/ps1;->OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/util/LinkedList;->add(Ljava/lang/Object;)Z

    goto :goto_12

    :cond_26
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    move-result v11

    const/4 v14, 0x1

    if-eq v11, v14, :cond_28

    const/4 v14, 0x2

    if-eq v11, v14, :cond_27

    invoke-interface {v13, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, [Llyiahf/vczjk/eb0;

    invoke-static {v10, v6, v11}, Llyiahf/vczjk/ps1;->OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;

    move-result-object v6

    invoke-virtual {v0, v1, v2, v9, v6}, Llyiahf/vczjk/n90;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V

    :goto_13
    const/16 v18, 0x1

    goto :goto_14

    :cond_27
    invoke-interface {v13, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, [Llyiahf/vczjk/eb0;

    invoke-static {v10, v6, v11}, Llyiahf/vczjk/ps1;->OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;

    move-result-object v6

    invoke-virtual {v0, v1, v2, v9, v6}, Llyiahf/vczjk/n90;->OooO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V

    goto :goto_13

    :cond_28
    const/4 v11, 0x0

    invoke-static {v10, v6, v11}, Llyiahf/vczjk/ps1;->OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;

    move-result-object v6

    invoke-virtual {v0, v1, v2, v9, v6}, Llyiahf/vczjk/n90;->OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/qs1;Llyiahf/vczjk/ps1;)V

    goto :goto_13

    :goto_14
    add-int/lit8 v5, v5, 0x1

    goto :goto_12

    :cond_29
    if-lez v5, :cond_2a

    goto/16 :goto_22

    :cond_2a
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v7

    const/4 v11, 0x0

    :goto_15
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3a

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v13, v3

    check-cast v13, Llyiahf/vczjk/ps1;

    iget v14, v13, Llyiahf/vczjk/ps1;->OooO0OO:I

    iget-object v15, v13, Llyiahf/vczjk/ps1;->OooO0Oo:[Llyiahf/vczjk/uqa;

    iget-object v3, v13, Llyiahf/vczjk/ps1;->OooO0O0:Llyiahf/vczjk/gn;

    const/4 v5, 0x1

    if-ne v14, v5, :cond_2d

    const/4 v4, 0x0

    aget-object v5, v15, v4

    iget-object v5, v5, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/eb0;

    invoke-static {v10, v3, v5}, Llyiahf/vczjk/n90;->OooO0oO(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;Llyiahf/vczjk/eb0;)Z

    move-result v6

    if-eqz v6, :cond_2c

    move-object v6, v3

    invoke-virtual {v13, v4}, Llyiahf/vczjk/ps1;->OooO0O0(I)Llyiahf/vczjk/xa7;

    move-result-object v3

    aget-object v5, v15, v4

    iget-object v13, v5, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/vm;

    iget-object v5, v5, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/t54;

    move/from16 v17, v4

    const/4 v4, 0x0

    move-object v14, v6

    move-object v6, v5

    move-object v5, v13

    move-object v13, v14

    move/from16 v14, v17

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object v3

    const/4 v5, 0x1

    new-array v0, v5, [Llyiahf/vczjk/ph8;

    aput-object v3, v0, v14

    invoke-virtual {v9, v13, v14, v0}, Llyiahf/vczjk/qs1;->OooO0OO(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;)V

    :cond_2b
    :goto_16
    move-object/from16 v2, p1

    move-object/from16 v1, p2

    const/16 v24, 0x7

    const/16 v25, 0x6

    goto/16 :goto_1a

    :cond_2c
    move-object v13, v3

    move v14, v4

    move-object/from16 v0, v26

    check-cast v0, Llyiahf/vczjk/fka;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/fka;->OooO00o(Llyiahf/vczjk/gn;)Z

    move-result v0

    invoke-static {v9, v13, v14, v0}, Llyiahf/vczjk/n90;->OooO(Llyiahf/vczjk/qs1;Llyiahf/vczjk/gn;ZZ)V

    if-eqz v5, :cond_2b

    check-cast v5, Llyiahf/vczjk/eh6;

    const/4 v4, 0x0

    iput-object v4, v5, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    goto :goto_16

    :cond_2d
    move-object v0, v3

    new-array v1, v14, [Llyiahf/vczjk/ph8;

    const/4 v2, -0x1

    move/from16 v21, v2

    const/4 v4, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    :goto_17
    if-ge v4, v14, :cond_33

    invoke-virtual {v0, v4}, Llyiahf/vczjk/gn;->o000OOo(I)Llyiahf/vczjk/vm;

    move-result-object v5

    aget-object v2, v15, v4

    iget-object v2, v2, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/eb0;

    invoke-virtual {v10, v5}, Llyiahf/vczjk/yn;->OooOOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/t54;

    move-result-object v6

    if-nez v2, :cond_2e

    const/4 v3, 0x0

    goto :goto_18

    :cond_2e
    invoke-virtual {v2}, Llyiahf/vczjk/eb0;->getFullName()Llyiahf/vczjk/xa7;

    move-result-object v3

    :goto_18
    if-eqz v2, :cond_2f

    invoke-virtual {v2}, Llyiahf/vczjk/eb0;->OooOoO0()Z

    move-result v2

    if-eqz v2, :cond_2f

    const/16 v18, 0x1

    add-int/lit8 v22, v22, 0x1

    move-object/from16 v2, p1

    move-object v8, v0

    move-object v12, v1

    const/16 v24, 0x7

    const/16 v25, 0x6

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object v3

    aput-object v3, v12, v4

    goto :goto_19

    :cond_2f
    move-object v8, v0

    move-object v12, v1

    const/16 v18, 0x1

    const/16 v24, 0x7

    const/16 v25, 0x6

    if-eqz v6, :cond_30

    add-int/lit8 v23, v23, 0x1

    move-object/from16 v0, p0

    move-object/from16 v2, p1

    move-object/from16 v1, p2

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object v3

    aput-object v3, v12, v4

    goto :goto_19

    :cond_30
    move-object/from16 v2, p1

    move-object/from16 v1, p2

    invoke-virtual {v10, v5}, Llyiahf/vczjk/yn;->OoooOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/wt5;

    move-result-object v0

    if-nez v0, :cond_32

    if-gez v21, :cond_31

    move/from16 v21, v4

    :cond_31
    :goto_19
    add-int/lit8 v4, v4, 0x1

    move-object v0, v8

    move-object v1, v12

    goto :goto_17

    :cond_32
    invoke-static {v1, v2, v5}, Llyiahf/vczjk/n90;->OooOO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/vm;)V

    const/16 v16, 0x0

    throw v16

    :cond_33
    move-object/from16 v2, p1

    move-object v8, v0

    move-object v12, v1

    const/16 v24, 0x7

    const/16 v25, 0x6

    move-object/from16 v1, p2

    if-gtz v22, :cond_37

    if-lez v23, :cond_34

    goto :goto_1b

    :cond_34
    const/16 v17, 0x0

    aget-object v0, v19, v17

    if-eqz v0, :cond_35

    goto :goto_1a

    :cond_35
    if-nez v11, :cond_36

    new-instance v11, Ljava/util/LinkedList;

    invoke-direct {v11}, Ljava/util/LinkedList;-><init>()V

    :cond_36
    invoke-interface {v11, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_1a
    move-object/from16 v0, p0

    goto/16 :goto_15

    :cond_37
    :goto_1b
    add-int v0, v22, v23

    if-ne v0, v14, :cond_38

    const/4 v6, 0x0

    invoke-virtual {v9, v8, v6, v12}, Llyiahf/vczjk/qs1;->OooO0OO(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;)V

    goto :goto_1a

    :cond_38
    const/4 v6, 0x0

    if-nez v22, :cond_39

    const/16 v18, 0x1

    add-int/lit8 v0, v23, 0x1

    if-ne v0, v14, :cond_39

    invoke-virtual {v9, v8, v6, v12, v6}, Llyiahf/vczjk/qs1;->OooO0O0(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;I)V

    goto :goto_1a

    :cond_39
    aget-object v0, v15, v21

    iget-object v0, v0, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vm;

    iget-object v3, v13, Llyiahf/vczjk/ps1;->OooO00o:Llyiahf/vczjk/yn;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/yn;->OooOOOO(Llyiahf/vczjk/pm;)V

    invoke-static/range {v21 .. v21}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {v0, v8}, [Ljava/lang/Object;

    move-result-object v0

    const-string v3, "Argument #%d of constructor %s has no property name annotation; must have name when multiple-parameter constructor annotated as Creator"

    invoke-virtual {v1, v2, v3, v0}, Llyiahf/vczjk/v72;->o000OO(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    const/16 v16, 0x0

    throw v16

    :cond_3a
    const/16 v16, 0x0

    const/16 v24, 0x7

    const/16 v25, 0x6

    if-eqz v11, :cond_48

    aget-object v0, v19, v25

    if-eqz v0, :cond_3b

    goto/16 :goto_23

    :cond_3b
    aget-object v0, v19, v24

    if-eqz v0, :cond_3c

    goto/16 :goto_23

    :cond_3c
    invoke-interface {v11}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v7

    move-object/from16 v8, v16

    move-object v11, v8

    :cond_3d
    :goto_1c
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_44

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v12, v0

    check-cast v12, Llyiahf/vczjk/gn;

    move-object/from16 v0, v26

    check-cast v0, Llyiahf/vczjk/fka;

    invoke-virtual {v0, v12}, Llyiahf/vczjk/fka;->OooO00o(Llyiahf/vczjk/gn;)Z

    move-result v0

    if-nez v0, :cond_3e

    goto :goto_1c

    :cond_3e
    invoke-virtual {v12}, Llyiahf/vczjk/gn;->o000000()I

    move-result v13

    new-array v14, v13, [Llyiahf/vczjk/ph8;

    const/4 v15, 0x0

    :goto_1d
    if-ge v15, v13, :cond_42

    invoke-virtual {v12, v15}, Llyiahf/vczjk/gn;->o000OOo(I)Llyiahf/vczjk/vm;

    move-result-object v5

    if-eqz v10, :cond_40

    invoke-virtual {v10, v5}, Llyiahf/vczjk/yn;->OooOo0(Llyiahf/vczjk/pm;)Llyiahf/vczjk/xa7;

    move-result-object v4

    if-eqz v4, :cond_3f

    move-object v3, v4

    goto :goto_1e

    :cond_3f
    invoke-virtual {v10, v5}, Llyiahf/vczjk/yn;->OooOOOO(Llyiahf/vczjk/pm;)V

    :cond_40
    move-object/from16 v3, v16

    :goto_1e
    if-eqz v3, :cond_3d

    invoke-virtual {v3}, Llyiahf/vczjk/xa7;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_41

    goto :goto_1c

    :cond_41
    invoke-virtual {v5}, Llyiahf/vczjk/vm;->o0OO00O()I

    move-result v4

    const/4 v6, 0x0

    move-object/from16 v0, p0

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/n90;->OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;

    move-result-object v3

    aput-object v3, v14, v15

    const/16 v18, 0x1

    add-int/lit8 v15, v15, 0x1

    goto :goto_1d

    :cond_42
    if-eqz v8, :cond_43

    move-object/from16 v14, v16

    goto :goto_1f

    :cond_43
    move-object v8, v12

    move-object v11, v14

    goto :goto_1c

    :cond_44
    move-object v14, v8

    :goto_1f
    if-eqz v14, :cond_48

    const/4 v6, 0x0

    invoke-virtual {v9, v14, v6, v11}, Llyiahf/vczjk/qs1;->OooO0OO(Llyiahf/vczjk/gn;Z[Llyiahf/vczjk/ph8;)V

    array-length v0, v11

    const/4 v6, 0x0

    :goto_20
    if-ge v6, v0, :cond_48

    aget-object v3, v11, v6

    iget-object v4, v3, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/h90;->OooO(Llyiahf/vczjk/xa7;)Z

    move-result v5

    if-nez v5, :cond_46

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v5

    invoke-interface {v3}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v28

    new-instance v26, Llyiahf/vczjk/bo8;

    invoke-virtual {v5}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v27

    const/16 v30, 0x0

    sget-object v31, Llyiahf/vczjk/eb0;->OooOOO0:Llyiahf/vczjk/fa4;

    move-object/from16 v29, v4

    invoke-direct/range {v26 .. v31}, Llyiahf/vczjk/bo8;-><init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/pm;Llyiahf/vczjk/xa7;Llyiahf/vczjk/wa7;Llyiahf/vczjk/fa4;)V

    move-object/from16 v4, v26

    move-object/from16 v3, v29

    invoke-virtual {v2, v3}, Llyiahf/vczjk/h90;->OooO(Llyiahf/vczjk/xa7;)Z

    move-result v3

    if-eqz v3, :cond_45

    goto :goto_21

    :cond_45
    invoke-virtual {v2}, Llyiahf/vczjk/h90;->OooO0O0()Ljava/util/List;

    move-result-object v3

    invoke-interface {v3, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_46
    :goto_21
    const/16 v18, 0x1

    add-int/lit8 v6, v6, 0x1

    goto :goto_20

    :cond_47
    :goto_22
    const/16 v24, 0x7

    const/16 v25, 0x6

    :cond_48
    :goto_23
    aget-object v0, v19, v25

    iget-object v2, v9, Llyiahf/vczjk/qs1;->OooO0oO:[Llyiahf/vczjk/ph8;

    invoke-virtual {v9, v1, v0, v2}, Llyiahf/vczjk/qs1;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/gn;[Llyiahf/vczjk/ph8;)Llyiahf/vczjk/x64;

    move-result-object v0

    const/16 v2, 0x8

    aget-object v3, v19, v2

    iget-object v4, v9, Llyiahf/vczjk/qs1;->OooO0oo:[Llyiahf/vczjk/ph8;

    invoke-virtual {v9, v1, v3, v4}, Llyiahf/vczjk/qs1;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/gn;[Llyiahf/vczjk/ph8;)Llyiahf/vczjk/x64;

    move-result-object v1

    iget-object v3, v9, Llyiahf/vczjk/qs1;->OooO00o:Llyiahf/vczjk/h90;

    new-instance v4, Llyiahf/vczjk/f59;

    iget-object v3, v3, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    invoke-direct {v4, v3}, Llyiahf/vczjk/f59;-><init>(Llyiahf/vczjk/x64;)V

    const/16 v17, 0x0

    aget-object v3, v19, v17

    aget-object v5, v19, v25

    iget-object v6, v9, Llyiahf/vczjk/qs1;->OooO0oO:[Llyiahf/vczjk/ph8;

    aget-object v7, v19, v24

    iget-object v8, v9, Llyiahf/vczjk/qs1;->OooO:[Llyiahf/vczjk/ph8;

    iput-object v3, v4, Llyiahf/vczjk/f59;->_defaultCreator:Llyiahf/vczjk/gn;

    iput-object v5, v4, Llyiahf/vczjk/f59;->_delegateCreator:Llyiahf/vczjk/gn;

    iput-object v0, v4, Llyiahf/vczjk/f59;->_delegateType:Llyiahf/vczjk/x64;

    iput-object v6, v4, Llyiahf/vczjk/f59;->_delegateArguments:[Llyiahf/vczjk/ph8;

    iput-object v7, v4, Llyiahf/vczjk/f59;->_withArgsCreator:Llyiahf/vczjk/gn;

    iput-object v8, v4, Llyiahf/vczjk/f59;->_constructorArguments:[Llyiahf/vczjk/ph8;

    aget-object v0, v19, v2

    iget-object v2, v9, Llyiahf/vczjk/qs1;->OooO0oo:[Llyiahf/vczjk/ph8;

    iput-object v0, v4, Llyiahf/vczjk/f59;->_arrayDelegateCreator:Llyiahf/vczjk/gn;

    iput-object v1, v4, Llyiahf/vczjk/f59;->_arrayDelegateType:Llyiahf/vczjk/x64;

    iput-object v2, v4, Llyiahf/vczjk/f59;->_arrayDelegateArguments:[Llyiahf/vczjk/ph8;

    const/16 v18, 0x1

    aget-object v0, v19, v18

    iput-object v0, v4, Llyiahf/vczjk/f59;->_fromStringCreator:Llyiahf/vczjk/gn;

    const/16 v20, 0x2

    aget-object v0, v19, v20

    iput-object v0, v4, Llyiahf/vczjk/f59;->_fromIntCreator:Llyiahf/vczjk/gn;

    const/4 v0, 0x3

    aget-object v0, v19, v0

    iput-object v0, v4, Llyiahf/vczjk/f59;->_fromLongCreator:Llyiahf/vczjk/gn;

    const/4 v0, 0x4

    aget-object v0, v19, v0

    iput-object v0, v4, Llyiahf/vczjk/f59;->_fromDoubleCreator:Llyiahf/vczjk/gn;

    const/4 v0, 0x5

    aget-object v0, v19, v0

    iput-object v0, v4, Llyiahf/vczjk/f59;->_fromBooleanCreator:Llyiahf/vczjk/gn;

    return-object v4
.end method

.method public final OooOO0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/xa7;ILlyiahf/vczjk/vm;Llyiahf/vczjk/t54;)Llyiahf/vczjk/rs1;
    .locals 10

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v6

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v0

    if-nez v0, :cond_0

    sget-object v1, Llyiahf/vczjk/wa7;->OooOOOo:Llyiahf/vczjk/wa7;

    :goto_0
    move-object v5, v1

    goto :goto_1

    :cond_0
    invoke-virtual {v0, p5}, Llyiahf/vczjk/yn;->Oooooo(Llyiahf/vczjk/pm;)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v0, p5}, Llyiahf/vczjk/yn;->Oooo00O(Llyiahf/vczjk/pm;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, p5}, Llyiahf/vczjk/yn;->Oooo0O0(Llyiahf/vczjk/pm;)Ljava/lang/Integer;

    move-result-object v3

    invoke-virtual {v0, p5}, Llyiahf/vczjk/yn;->Oooo000(Llyiahf/vczjk/pm;)Ljava/lang/String;

    move-result-object v5

    invoke-static {v1, v2, v3, v5}, Llyiahf/vczjk/wa7;->OooO00o(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)Llyiahf/vczjk/wa7;

    move-result-object v1

    goto :goto_0

    :goto_1
    invoke-virtual {p5}, Llyiahf/vczjk/vm;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {p0, p1, p5, v1}, Llyiahf/vczjk/n90;->OooOOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v2

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/cb0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v3, 0x0

    move-object v1, p3

    move-object v4, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/cb0;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/pm;Llyiahf/vczjk/wa7;)V

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/u3a;

    if-nez v1, :cond_1

    invoke-virtual {p0, v6, v2}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object v1

    :cond_1
    move-object v4, v1

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v3

    invoke-virtual {v0}, Llyiahf/vczjk/cb0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v6

    const/4 v7, 0x0

    if-eqz v6, :cond_3

    if-eqz v1, :cond_2

    invoke-virtual {v1, v6}, Llyiahf/vczjk/yn;->OoooO(Llyiahf/vczjk/pm;)Llyiahf/vczjk/ac4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ac4;->OooO0O0()Llyiahf/vczjk/d56;

    move-result-object v7

    invoke-virtual {v1}, Llyiahf/vczjk/ac4;->OooO00o()Llyiahf/vczjk/d56;

    move-result-object v1

    goto :goto_2

    :cond_2
    move-object v1, v7

    :goto_2
    invoke-virtual {v0}, Llyiahf/vczjk/cb0;->getType()Llyiahf/vczjk/x64;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v3, v6}, Llyiahf/vczjk/fc5;->OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;

    goto :goto_3

    :cond_3
    move-object v1, v7

    :goto_3
    invoke-virtual {v3}, Llyiahf/vczjk/fc5;->OooOoo0()Llyiahf/vczjk/ac4;

    move-result-object v3

    if-nez v7, :cond_4

    invoke-virtual {v3}, Llyiahf/vczjk/ac4;->OooO0O0()Llyiahf/vczjk/d56;

    move-result-object v7

    :cond_4
    if-nez v1, :cond_5

    invoke-virtual {v3}, Llyiahf/vczjk/ac4;->OooO00o()Llyiahf/vczjk/d56;

    move-result-object v1

    :cond_5
    if-nez v7, :cond_7

    if-eqz v1, :cond_6

    goto :goto_5

    :cond_6
    :goto_4
    move-object v9, v5

    goto :goto_6

    :cond_7
    :goto_5
    invoke-virtual {v5, v7, v1}, Llyiahf/vczjk/wa7;->OooO0Oo(Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)Llyiahf/vczjk/wa7;

    move-result-object v5

    goto :goto_4

    :goto_6
    iget-object v3, v0, Llyiahf/vczjk/cb0;->_wrapperName:Llyiahf/vczjk/xa7;

    iget-object p2, p2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    iget-object v5, p2, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    new-instance v0, Llyiahf/vczjk/rs1;

    move-object v1, p3

    move v7, p4

    move-object v6, p5

    move-object/from16 v8, p6

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/rs1;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;Llyiahf/vczjk/vm;ILlyiahf/vczjk/t54;Llyiahf/vczjk/wa7;)V

    invoke-static {p1, p5}, Llyiahf/vczjk/n90;->OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/u34;)Llyiahf/vczjk/e94;

    move-result-object p2

    if-nez p2, :cond_8

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/e94;

    :cond_8
    if-eqz p2, :cond_9

    invoke-virtual {p1, p2, v0, v2}, Llyiahf/vczjk/v72;->o000000(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/rs1;->Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rs1;

    return-object p1

    :cond_9
    return-object v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/nca;
    .locals 4

    invoke-virtual {p2}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v1

    iget-object v2, p1, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/yn;->OoooOo0(Llyiahf/vczjk/hm;)Ljava/lang/Object;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    instance-of v3, v1, Llyiahf/vczjk/nca;

    if-eqz v3, :cond_0

    check-cast v1, Llyiahf/vczjk/nca;

    goto :goto_1

    :cond_0
    check-cast v1, Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOOo(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_1

    goto :goto_0

    :cond_1
    const-class v3, Llyiahf/vczjk/nca;

    invoke-virtual {v3, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    invoke-static {v1, v0}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/nca;

    goto :goto_1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "AnnotationIntrospector returned Class "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-string v0, "; expected Class<ValueInstantiator>"

    invoke-static {v1, p2, v0}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    :goto_0
    move-object v1, v2

    :goto_1
    if-nez v1, :cond_c

    invoke-virtual {p1}, Llyiahf/vczjk/h90;->OooO0oO()Ljava/lang/Class;

    move-result-object v0

    const-class v1, Llyiahf/vczjk/ia4;

    if-ne v0, v1, :cond_4

    new-instance v2, Llyiahf/vczjk/ja4;

    const-class v0, Llyiahf/vczjk/ia4;

    invoke-direct {v2, v0}, Llyiahf/vczjk/mca;-><init>(Ljava/lang/Class;)V

    goto :goto_2

    :cond_4
    const-class v1, Ljava/util/Collection;

    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v1

    if-eqz v1, :cond_7

    const-class v1, Ljava/util/ArrayList;

    if-ne v0, v1, :cond_5

    sget-object v2, Llyiahf/vczjk/n54;->OooOOO0:Llyiahf/vczjk/n54;

    goto :goto_2

    :cond_5
    sget-object v1, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    if-ne v3, v0, :cond_6

    new-instance v2, Llyiahf/vczjk/o54;

    invoke-direct {v2, v1}, Llyiahf/vczjk/o54;-><init>(Ljava/lang/Object;)V

    goto :goto_2

    :cond_6
    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    if-ne v3, v0, :cond_a

    new-instance v2, Llyiahf/vczjk/o54;

    invoke-direct {v2, v1}, Llyiahf/vczjk/o54;-><init>(Ljava/lang/Object;)V

    goto :goto_2

    :cond_7
    const-class v1, Ljava/util/Map;

    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v1

    if-eqz v1, :cond_a

    const-class v1, Ljava/util/LinkedHashMap;

    if-ne v0, v1, :cond_8

    sget-object v2, Llyiahf/vczjk/q54;->OooOOO0:Llyiahf/vczjk/q54;

    goto :goto_2

    :cond_8
    const-class v1, Ljava/util/HashMap;

    if-ne v0, v1, :cond_9

    sget-object v2, Llyiahf/vczjk/p54;->OooOOO0:Llyiahf/vczjk/p54;

    goto :goto_2

    :cond_9
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    if-ne v3, v0, :cond_a

    new-instance v2, Llyiahf/vczjk/o54;

    invoke-direct {v2, v1}, Llyiahf/vczjk/o54;-><init>(Ljava/lang/Object;)V

    :cond_a
    :goto_2
    if-nez v2, :cond_b

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/n90;->OooO0oo(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/f59;

    move-result-object v1

    goto :goto_3

    :cond_b
    move-object v1, v2

    :cond_c
    :goto_3
    iget-object p1, p0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    iget-object p1, p1, Llyiahf/vczjk/z82;->_valueInstantiators:[Llyiahf/vczjk/oca;

    array-length p1, p1

    if-lez p1, :cond_d

    const/4 p1, 0x1

    goto :goto_4

    :cond_d
    const/4 p1, 0x0

    :goto_4
    if-eqz p1, :cond_f

    iget-object p1, p0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    new-instance p2, Llyiahf/vczjk/yx;

    iget-object p1, p1, Llyiahf/vczjk/z82;->_valueInstantiators:[Llyiahf/vczjk/oca;

    invoke-direct {p2, p1}, Llyiahf/vczjk/yx;-><init>([Ljava/lang/Object;)V

    invoke-virtual {p2}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result p1

    if-nez p1, :cond_e

    goto :goto_5

    :cond_e
    invoke-static {p2}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_f
    :goto_5
    invoke-virtual {v1}, Llyiahf/vczjk/nca;->OooOoOO()Llyiahf/vczjk/vm;

    move-result-object p1

    if-nez p1, :cond_10

    return-object v1

    :cond_10
    invoke-virtual {v1}, Llyiahf/vczjk/nca;->OooOoOO()Llyiahf/vczjk/vm;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/vm;->oo0o0Oo()Llyiahf/vczjk/gn;

    move-result-object p2

    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Argument #"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/vm;->o0OO00O()I

    move-result p1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p1, " of constructor "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " has no property name annotation; must have name when multiple-parameter constructor annotated as Creator"

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooOOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 5

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v0

    if-nez v0, :cond_0

    return-object p3

    :cond_0
    invoke-virtual {p3}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-virtual {v0, p2}, Llyiahf/vczjk/yn;->OooOOo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/v72;->o0000oo(Ljava/lang/Object;)Llyiahf/vczjk/ti4;

    move-result-object v1

    if-eqz v1, :cond_1

    check-cast p3, Llyiahf/vczjk/ub5;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ub5;->o0O0O00(Llyiahf/vczjk/ti4;)Llyiahf/vczjk/wb5;

    move-result-object p3

    :cond_1
    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OoooOo0()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-virtual {v0, p2}, Llyiahf/vczjk/yn;->OooO0OO(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/v72;->OoooooO(Ljava/lang/Object;)Llyiahf/vczjk/e94;

    move-result-object v1

    if-eqz v1, :cond_2

    invoke-virtual {p3, v1}, Llyiahf/vczjk/x64;->o00oO0O(Llyiahf/vczjk/e94;)Llyiahf/vczjk/x64;

    move-result-object p3

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v2

    invoke-virtual {v2, v1, p2, p3}, Llyiahf/vczjk/yn;->OooOooo(Llyiahf/vczjk/fc5;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;

    move-result-object v2

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v3

    if-nez v2, :cond_3

    invoke-virtual {p0, v1, v3}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object v1

    goto :goto_0

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/fc5;->OooOooo()Llyiahf/vczjk/k99;

    move-result-object v4

    invoke-virtual {v4, v1, p2, v3}, Llyiahf/vczjk/k99;->OooO0Oo(Llyiahf/vczjk/t72;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Ljava/util/ArrayList;

    move-result-object v4

    check-cast v2, Llyiahf/vczjk/e59;

    invoke-virtual {v2, v1, v3, v4}, Llyiahf/vczjk/e59;->OooO00o(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;Ljava/util/ArrayList;)Llyiahf/vczjk/v3a;

    move-result-object v1

    :goto_0
    if-eqz v1, :cond_4

    invoke-virtual {p3, v1}, Llyiahf/vczjk/x64;->o00oO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object p3

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v2

    invoke-virtual {v2, v1, p2, p3}, Llyiahf/vczjk/yn;->Oooo0OO(Llyiahf/vczjk/fc5;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;

    move-result-object v2

    if-nez v2, :cond_5

    invoke-virtual {p0, v1, p3}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object v1

    goto :goto_1

    :cond_5
    invoke-virtual {v1}, Llyiahf/vczjk/fc5;->OooOooo()Llyiahf/vczjk/k99;

    move-result-object v3

    invoke-virtual {v3, v1, p2, p3}, Llyiahf/vczjk/k99;->OooO0Oo(Llyiahf/vczjk/t72;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Ljava/util/ArrayList;

    move-result-object v3

    :try_start_0
    check-cast v2, Llyiahf/vczjk/e59;

    invoke-virtual {v2, v1, p3, v3}, Llyiahf/vczjk/e59;->OooO00o(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;Ljava/util/ArrayList;)Llyiahf/vczjk/v3a;

    move-result-object v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    :goto_1
    if-eqz v1, :cond_6

    invoke-virtual {p3, v1}, Llyiahf/vczjk/x64;->o0ooOoO(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object p3

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object p1

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/yn;->ooOO(Llyiahf/vczjk/t72;Llyiahf/vczjk/u34;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1

    :catch_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/d44;

    const/4 v1, 0x0

    invoke-direct {v0, v1, p2, p3}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    invoke-virtual {v0, p1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    throw v0
.end method
