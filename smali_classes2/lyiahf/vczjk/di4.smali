.class public final Llyiahf/vczjk/di4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bi4;


# static fields
.field public static final synthetic OooO0o0:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/uk4;

.field public final OooO0O0:Llyiahf/vczjk/wm7;

.field public final OooO0OO:Llyiahf/vczjk/wm7;

.field public final OooO0Oo:Llyiahf/vczjk/wm7;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/di4;

    const-string v2, "classifier"

    const-string v3, "getClassifier()Lkotlin/reflect/KClassifier;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "arguments"

    const-string v5, "getArguments()Ljava/util/List;"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/4 v2, 0x2

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/di4;->OooO0o0:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/le3;)V
    .locals 3

    const-string v0, "type"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    instance-of p1, p2, Llyiahf/vczjk/wm7;

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/wm7;

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-nez p1, :cond_2

    if-eqz p2, :cond_1

    invoke-static {v0, p2}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object p1

    goto :goto_1

    :cond_1
    move-object p1, v0

    :cond_2
    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/di4;->OooO0O0:Llyiahf/vczjk/wm7;

    new-instance p1, Llyiahf/vczjk/ci4;

    const/4 v1, 0x0

    invoke-direct {p1, p0, v1}, Llyiahf/vczjk/ci4;-><init>(Llyiahf/vczjk/di4;I)V

    invoke-static {v0, p1}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/di4;->OooO0OO:Llyiahf/vczjk/wm7;

    new-instance p1, Llyiahf/vczjk/o0O000;

    const/16 v1, 0x14

    const/4 v2, 0x0

    invoke-direct {p1, v1, p0, p2, v2}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-static {v0, p1}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/di4;->OooO0Oo:Llyiahf/vczjk/wm7;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/tf4;
    .locals 3

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/by0;

    const/4 v2, 0x0

    if-eqz v1, :cond_7

    check-cast v0, Llyiahf/vczjk/by0;

    invoke-static {v0}, Llyiahf/vczjk/mba;->OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;

    move-result-object v0

    if-nez v0, :cond_0

    goto/16 :goto_2

    :cond_0
    invoke-virtual {v0}, Ljava/lang/Class;->isArray()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/d21;->o00000oO(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z4a;

    if-eqz p1, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object p1

    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p0, p1}, Llyiahf/vczjk/di4;->OooO00o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/tf4;

    move-result-object p1

    if-eqz p1, :cond_2

    new-instance v0, Llyiahf/vczjk/of4;

    invoke-static {p1}, Llyiahf/vczjk/mc4;->Oooo0(Llyiahf/vczjk/tf4;)Llyiahf/vczjk/gf4;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object p1

    const/4 v1, 0x0

    invoke-static {p1, v1}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/of4;-><init>(Ljava/lang/Class;)V

    return-object v0

    :cond_2
    new-instance p1, Llyiahf/vczjk/es1;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot determine classifier for array element type: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    :goto_0
    new-instance p1, Llyiahf/vczjk/of4;

    invoke-direct {p1, v0}, Llyiahf/vczjk/of4;-><init>(Ljava/lang/Class;)V

    return-object p1

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result p1

    if-nez p1, :cond_6

    new-instance p1, Llyiahf/vczjk/of4;

    sget-object v1, Llyiahf/vczjk/rl7;->OooO0O0:Ljava/util/Map;

    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Class;

    if-nez v1, :cond_5

    goto :goto_1

    :cond_5
    move-object v0, v1

    :goto_1
    invoke-direct {p1, v0}, Llyiahf/vczjk/of4;-><init>(Ljava/lang/Class;)V

    return-object p1

    :cond_6
    new-instance p1, Llyiahf/vczjk/of4;

    invoke-direct {p1, v0}, Llyiahf/vczjk/of4;-><init>(Ljava/lang/Class;)V

    return-object p1

    :cond_7
    instance-of p1, v0, Llyiahf/vczjk/t4a;

    if-eqz p1, :cond_8

    new-instance p1, Llyiahf/vczjk/fi4;

    check-cast v0, Llyiahf/vczjk/t4a;

    invoke-direct {p1, v2, v0}, Llyiahf/vczjk/fi4;-><init>(Llyiahf/vczjk/gi4;Llyiahf/vczjk/t4a;)V

    return-object p1

    :cond_8
    instance-of p1, v0, Llyiahf/vczjk/a3a;

    if-nez p1, :cond_9

    :goto_2
    return-object v2

    :cond_9
    new-instance p1, Llyiahf/vczjk/s26;

    const-string v0, "An operation is not implemented: Type alias classifiers are not yet supported"

    invoke-direct {p1, v0}, Ljava/lang/Error;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0O0()Ljava/util/List;
    .locals 2

    sget-object v0, Llyiahf/vczjk/di4;->OooO0o0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    iget-object v0, p0, Llyiahf/vczjk/di4;->OooO0Oo:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/List;

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/tf4;
    .locals 2

    sget-object v0, Llyiahf/vczjk/di4;->OooO0o0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    iget-object v0, p0, Llyiahf/vczjk/di4;->OooO0OO:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tf4;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/di4;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/di4;

    iget-object v0, p1, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    iget-object v1, p0, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/di4;->OooO0OO()Llyiahf/vczjk/tf4;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/di4;->OooO0OO()Llyiahf/vczjk/tf4;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/di4;->OooO0O0()Ljava/util/List;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/di4;->OooO0O0()Ljava/util/List;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    invoke-virtual {p0}, Llyiahf/vczjk/di4;->OooO0OO()Llyiahf/vczjk/tf4;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    add-int/2addr v0, v1

    mul-int/lit8 v0, v0, 0x1f

    invoke-virtual {p0}, Llyiahf/vczjk/di4;->OooO0O0()Ljava/util/List;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    sget-object v0, Llyiahf/vczjk/en7;->OooO00o:Llyiahf/vczjk/h72;

    iget-object v0, p0, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-static {v0}, Llyiahf/vczjk/en7;->OooO0Oo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
