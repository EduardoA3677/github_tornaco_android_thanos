.class public final Llyiahf/vczjk/kr4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f07;


# static fields
.field public static final synthetic OooO0oo:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ld9;

.field public final OooO0O0:Llyiahf/vczjk/sl7;

.field public final OooO0OO:Llyiahf/vczjk/n45;

.field public final OooO0Oo:Llyiahf/vczjk/o45;

.field public final OooO0o:Llyiahf/vczjk/o45;

.field public final OooO0o0:Llyiahf/vczjk/hz7;

.field public final OooO0oO:Z


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/kr4;

    const-string v2, "fqName"

    const-string v3, "getFqName()Lorg/jetbrains/kotlin/name/FqName;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "type"

    const-string v5, "getType()Lorg/jetbrains/kotlin/types/SimpleType;"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v3

    const-string v5, "allValueArguments"

    const-string v6, "getAllValueArguments()Ljava/util/Map;"

    invoke-static {v1, v5, v6, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/4 v2, 0x3

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v3, v2, v0

    const/4 v0, 0x2

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/kr4;->OooO0oo:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;Z)V
    .locals 3

    const-string v0, "c"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "javaAnnotation"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/kr4;->OooO00o:Llyiahf/vczjk/ld9;

    iput-object p1, p0, Llyiahf/vczjk/kr4;->OooO0O0:Llyiahf/vczjk/sl7;

    iget-object p2, p2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/s64;

    iget-object v0, p2, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v1, Llyiahf/vczjk/jr4;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/jr4;-><init>(Llyiahf/vczjk/kr4;I)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/n45;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v2, p0, Llyiahf/vczjk/kr4;->OooO0OO:Llyiahf/vczjk/n45;

    new-instance v1, Llyiahf/vczjk/jr4;

    const/4 v2, 0x1

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/jr4;-><init>(Llyiahf/vczjk/kr4;I)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/o45;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v2, p0, Llyiahf/vczjk/kr4;->OooO0Oo:Llyiahf/vczjk/o45;

    iget-object p2, p2, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/kr4;->OooO0o0:Llyiahf/vczjk/hz7;

    new-instance p1, Llyiahf/vczjk/jr4;

    const/4 p2, 0x2

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/jr4;-><init>(Llyiahf/vczjk/kr4;I)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/o45;

    invoke-direct {p2, v0, p1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p2, p0, Llyiahf/vczjk/kr4;->OooO0o:Llyiahf/vczjk/o45;

    iput-boolean p3, p0, Llyiahf/vczjk/kr4;->OooO0oO:Z

    return-void
.end method


# virtual methods
.method public final OooO()Ljava/util/Map;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/kr4;->OooO0o:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/kr4;->OooO0oo:[Llyiahf/vczjk/th4;

    const/4 v2, 0x2

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map;

    return-object v0
.end method

.method public final OooO00o(Llyiahf/vczjk/y54;)Llyiahf/vczjk/ij1;
    .locals 7

    const/4 v0, 0x1

    instance-of v1, p1, Llyiahf/vczjk/jm7;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    sget-object v0, Llyiahf/vczjk/sp3;->OooOOO:Llyiahf/vczjk/sp3;

    check-cast p1, Llyiahf/vczjk/jm7;

    iget-object p1, p1, Llyiahf/vczjk/jm7;->OooO0O0:Ljava/lang/Object;

    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/sp3;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/dm5;)Llyiahf/vczjk/ij1;

    move-result-object p1

    return-object p1

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/hm7;

    if-eqz v1, :cond_2

    check-cast p1, Llyiahf/vczjk/hm7;

    iget-object v0, p1, Llyiahf/vczjk/hm7;->OooO0O0:Ljava/lang/Enum;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->isEnum()Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Ljava/lang/Class;->getEnclosingClass()Ljava/lang/Class;

    move-result-object v0

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v0

    iget-object p1, p1, Llyiahf/vczjk/hm7;->OooO0O0:Ljava/lang/Enum;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/zp2;

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/zp2;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/qt5;)V

    return-object v1

    :cond_2
    instance-of v1, p1, Llyiahf/vczjk/vl7;

    const/4 v3, 0x0

    iget-object v4, p0, Llyiahf/vczjk/kr4;->OooO00o:Llyiahf/vczjk/ld9;

    if-eqz v1, :cond_9

    check-cast p1, Llyiahf/vczjk/vl7;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/tl7;

    iget-object v1, v1, Llyiahf/vczjk/tl7;->OooO00o:Llyiahf/vczjk/qt5;

    if-nez v1, :cond_3

    sget-object v1, Llyiahf/vczjk/dd4;->OooO0O0:Llyiahf/vczjk/qt5;

    :cond_3
    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/vl7;->OooO00o()Ljava/util/ArrayList;

    move-result-object p1

    iget-object v5, p0, Llyiahf/vczjk/kr4;->OooO0Oo:Llyiahf/vczjk/o45;

    sget-object v6, Llyiahf/vczjk/kr4;->OooO0oo:[Llyiahf/vczjk/th4;

    aget-object v0, v6, v0

    invoke-static {v5, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dp8;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-eqz v0, :cond_4

    goto/16 :goto_5

    :cond_4
    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0Oo(Llyiahf/vczjk/un;)Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v1, v0}, Llyiahf/vczjk/jp8;->OooOo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/by0;)Llyiahf/vczjk/tca;

    move-result-object v0

    if-eqz v0, :cond_5

    check-cast v0, Llyiahf/vczjk/bda;

    invoke-virtual {v0}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v0

    if-nez v0, :cond_6

    :cond_5
    iget-object v0, v4, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    iget-object v0, v0, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    sget-object v1, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    sget-object v1, Llyiahf/vczjk/tq2;->Oooo0oO:Llyiahf/vczjk/tq2;

    new-array v3, v3, [Ljava/lang/String;

    invoke-static {v1, v3}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hk4;->OooO0oo(Llyiahf/vczjk/iaa;)Llyiahf/vczjk/dp8;

    move-result-object v0

    :cond_6
    new-instance v1, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {p1, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_8

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/y54;

    invoke-virtual {p0, v3}, Llyiahf/vczjk/kr4;->OooO00o(Llyiahf/vczjk/y54;)Llyiahf/vczjk/ij1;

    move-result-object v3

    if-nez v3, :cond_7

    new-instance v3, Llyiahf/vczjk/t46;

    invoke-direct {v3, v2}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    :cond_7
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_8
    new-instance p1, Llyiahf/vczjk/s5a;

    invoke-direct {p1, v1, v0}, Llyiahf/vczjk/s5a;-><init>(Ljava/util/List;Llyiahf/vczjk/uk4;)V

    return-object p1

    :cond_9
    instance-of v1, p1, Llyiahf/vczjk/ul7;

    if-eqz v1, :cond_a

    check-cast p1, Llyiahf/vczjk/ul7;

    new-instance v0, Llyiahf/vczjk/sl7;

    iget-object p1, p1, Llyiahf/vczjk/ul7;->OooO0O0:Ljava/lang/annotation/Annotation;

    invoke-direct {v0, p1}, Llyiahf/vczjk/sl7;-><init>(Ljava/lang/annotation/Annotation;)V

    new-instance p1, Llyiahf/vczjk/io;

    new-instance v1, Llyiahf/vczjk/kr4;

    invoke-direct {v1, v0, v4, v3}, Llyiahf/vczjk/kr4;-><init>(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;Z)V

    invoke-direct {p1, v1}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    return-object p1

    :cond_a
    instance-of v1, p1, Llyiahf/vczjk/dm7;

    if-eqz v1, :cond_13

    check-cast p1, Llyiahf/vczjk/dm7;

    iget-object p1, p1, Llyiahf/vczjk/dm7;->OooO0O0:Ljava/lang/Class;

    invoke-virtual {p1}, Ljava/lang/Class;->isPrimitive()Z

    move-result v1

    if-eqz v1, :cond_b

    new-instance v1, Llyiahf/vczjk/nm7;

    invoke-direct {v1, p1}, Llyiahf/vczjk/nm7;-><init>(Ljava/lang/Class;)V

    goto :goto_3

    :cond_b
    instance-of v1, p1, Ljava/lang/reflect/GenericArrayType;

    if-nez v1, :cond_e

    invoke-virtual {p1}, Ljava/lang/Class;->isArray()Z

    move-result v1

    if-eqz v1, :cond_c

    goto :goto_2

    :cond_c
    instance-of v1, p1, Ljava/lang/reflect/WildcardType;

    if-eqz v1, :cond_d

    new-instance v1, Llyiahf/vczjk/sm7;

    check-cast p1, Ljava/lang/reflect/WildcardType;

    invoke-direct {v1, p1}, Llyiahf/vczjk/sm7;-><init>(Ljava/lang/reflect/WildcardType;)V

    goto :goto_3

    :cond_d
    new-instance v1, Llyiahf/vczjk/em7;

    invoke-direct {v1, p1}, Llyiahf/vczjk/em7;-><init>(Ljava/lang/reflect/Type;)V

    goto :goto_3

    :cond_e
    :goto_2
    new-instance v1, Llyiahf/vczjk/wl7;

    invoke-direct {v1, p1}, Llyiahf/vczjk/wl7;-><init>(Ljava/lang/reflect/Type;)V

    :goto_3
    iget-object p1, v4, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uqa;

    sget-object v4, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v5, 0x7

    invoke-static {v4, v3, v2, v5}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v4

    invoke-virtual {p1, v1, v4}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-eqz v1, :cond_f

    goto :goto_5

    :cond_f
    move-object v1, p1

    move v4, v3

    :goto_4
    invoke-static {v1}, Llyiahf/vczjk/hk4;->OooOoO(Llyiahf/vczjk/uk4;)Z

    move-result v5

    if-eqz v5, :cond_10

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/z4a;

    invoke-virtual {v1}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v1

    const-string v5, "getType(...)"

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    add-int/2addr v4, v0

    goto :goto_4

    :cond_10
    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_12

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object v0

    if-nez v0, :cond_11

    new-instance v0, Llyiahf/vczjk/sf4;

    new-instance v1, Llyiahf/vczjk/pf4;

    invoke-direct {v1, p1}, Llyiahf/vczjk/pf4;-><init>(Llyiahf/vczjk/uk4;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    return-object v0

    :cond_11
    new-instance p1, Llyiahf/vczjk/sf4;

    invoke-direct {p1, v0, v4}, Llyiahf/vczjk/sf4;-><init>(Llyiahf/vczjk/hy0;I)V

    return-object p1

    :cond_12
    instance-of p1, v0, Llyiahf/vczjk/t4a;

    if-eqz p1, :cond_13

    new-instance p1, Llyiahf/vczjk/sf4;

    sget-object v0, Llyiahf/vczjk/w09;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-direct {p1, v1, v3}, Llyiahf/vczjk/sf4;-><init>(Llyiahf/vczjk/hy0;I)V

    return-object p1

    :cond_13
    :goto_5
    return-object v2
.end method

.method public final OooO0oO()Llyiahf/vczjk/sx8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kr4;->OooO0o0:Llyiahf/vczjk/hz7;

    return-object v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/hc3;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/kr4;->OooO0OO:Llyiahf/vczjk/n45;

    sget-object v1, Llyiahf/vczjk/kr4;->OooO0oo:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    const-string v2, "<this>"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "p"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/n45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/hc3;

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/uk4;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/kr4;->OooO0Oo:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/kr4;->OooO0oo:[Llyiahf/vczjk/th4;

    const/4 v2, 0x1

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dp8;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    sget-object v0, Llyiahf/vczjk/h72;->OooO0OO:Llyiahf/vczjk/h72;

    const/4 v1, 0x0

    invoke-virtual {v0, p0, v1}, Llyiahf/vczjk/h72;->OooOo(Llyiahf/vczjk/un;Llyiahf/vczjk/fo;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
