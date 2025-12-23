.class public final Llyiahf/vczjk/zk4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/zk4;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/zk4;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/zk4;->OooO00o:Llyiahf/vczjk/zk4;

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/dp8;
    .locals 11

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/oq0;

    const/16 v2, 0xa

    const/4 v3, 0x0

    if-eqz v1, :cond_4

    check-cast v0, Llyiahf/vczjk/oq0;

    iget-object v1, v0, Llyiahf/vczjk/oq0;->OooO00o:Llyiahf/vczjk/z4a;

    invoke-virtual {v1}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/cda;->OooOOO:Llyiahf/vczjk/cda;

    if-ne v4, v5, :cond_0

    goto :goto_0

    :cond_0
    move-object v1, v3

    :goto_0
    if-eqz v1, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v1

    move-object v7, v1

    goto :goto_1

    :cond_1
    move-object v7, v3

    :goto_1
    iget-object v1, v0, Llyiahf/vczjk/oq0;->OooO0O0:Llyiahf/vczjk/n06;

    if-nez v1, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/oq0;->OooO0O0()Ljava/util/Collection;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    new-instance v4, Ljava/util/ArrayList;

    invoke-static {v1, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/uk4;

    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v2

    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_2
    new-instance v1, Llyiahf/vczjk/n06;

    const-string v2, "projection"

    iget-object v5, v0, Llyiahf/vczjk/oq0;->OooO00o:Llyiahf/vczjk/z4a;

    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/b82;

    const/4 v6, 0x1

    invoke-direct {v2, v6, v4}, Llyiahf/vczjk/b82;-><init>(ILjava/util/ArrayList;)V

    const/16 v4, 0x8

    invoke-direct {v1, v5, v2, v3, v4}, Llyiahf/vczjk/n06;-><init>(Llyiahf/vczjk/z4a;Llyiahf/vczjk/b82;Llyiahf/vczjk/t4a;I)V

    iput-object v1, v0, Llyiahf/vczjk/oq0;->OooO0O0:Llyiahf/vczjk/n06;

    :cond_3
    new-instance v4, Llyiahf/vczjk/m06;

    sget-object v5, Llyiahf/vczjk/kq0;->OooOOO0:Llyiahf/vczjk/kq0;

    iget-object v6, v0, Llyiahf/vczjk/oq0;->OooO0O0:Llyiahf/vczjk/n06;

    invoke-static {v6}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object v8

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v9

    const/16 v10, 0x20

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/m06;-><init>(Llyiahf/vczjk/kq0;Llyiahf/vczjk/n06;Llyiahf/vczjk/iaa;Llyiahf/vczjk/d3a;ZI)V

    return-object v4

    :cond_4
    instance-of v1, v0, Llyiahf/vczjk/m34;

    if-eqz v1, :cond_9

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v1

    if-eqz v1, :cond_9

    check-cast v0, Llyiahf/vczjk/m34;

    iget-object p0, v0, Llyiahf/vczjk/m34;->OooO0O0:Ljava/util/LinkedHashSet;

    new-instance v1, Ljava/util/ArrayList;

    invoke-static {p0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    const/4 v2, 0x0

    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/uk4;

    invoke-static {v2}, Llyiahf/vczjk/fu6;->OooOo0(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/4 v2, 0x1

    goto :goto_3

    :cond_5
    if-nez v2, :cond_6

    goto :goto_4

    :cond_6
    iget-object p0, v0, Llyiahf/vczjk/m34;->OooO00o:Llyiahf/vczjk/uk4;

    if-eqz p0, :cond_7

    invoke-static {p0}, Llyiahf/vczjk/fu6;->OooOo0(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object v3

    :cond_7
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    new-instance p0, Ljava/util/LinkedHashSet;

    invoke-direct {p0, v1}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    new-instance v1, Llyiahf/vczjk/m34;

    invoke-direct {v1, p0}, Llyiahf/vczjk/m34;-><init>(Ljava/util/AbstractCollection;)V

    iput-object v3, v1, Llyiahf/vczjk/m34;->OooO00o:Llyiahf/vczjk/uk4;

    move-object v3, v1

    :goto_4
    if-nez v3, :cond_8

    goto :goto_5

    :cond_8
    move-object v0, v3

    :goto_5
    invoke-virtual {v0}, Llyiahf/vczjk/m34;->OooO0o()Llyiahf/vczjk/dp8;

    move-result-object p0

    :cond_9
    return-object p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/iaa;
    .locals 9

    const-string v0, "type"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/uk4;

    if-eqz v0, :cond_5

    check-cast p1, Llyiahf/vczjk/uk4;

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p1

    instance-of v0, p1, Llyiahf/vczjk/dp8;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/dp8;

    invoke-static {v0}, Llyiahf/vczjk/zk4;->OooO0O0(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/dp8;

    move-result-object v0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/k23;

    if-eqz v0, :cond_4

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/k23;

    iget-object v1, v0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-static {v1}, Llyiahf/vczjk/zk4;->OooO0O0(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/dp8;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-static {v0}, Llyiahf/vczjk/zk4;->OooO0O0(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/dp8;

    move-result-object v3

    if-ne v2, v1, :cond_2

    if-eq v3, v0, :cond_1

    goto :goto_0

    :cond_1
    move-object v0, p1

    goto :goto_1

    :cond_2
    :goto_0
    invoke-static {v2, v3}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object v0

    :goto_1
    new-instance v1, Llyiahf/vczjk/o00000;

    const-class v4, Llyiahf/vczjk/zk4;

    const-string v5, "prepareType"

    const/4 v2, 0x1

    const-string v6, "prepareType(Lorg/jetbrains/kotlin/types/model/KotlinTypeMarker;)Lorg/jetbrains/kotlin/types/UnwrappedType;"

    const/4 v7, 0x0

    const/16 v8, 0x8

    move-object v3, p0

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object p1

    if-eqz p1, :cond_3

    invoke-virtual {v1, p1}, Llyiahf/vczjk/o00000;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uk4;

    goto :goto_2

    :cond_3
    const/4 p1, 0x0

    :goto_2
    invoke-static {v0, p1}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p1

    return-object p1

    :cond_4
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_5
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Failed requirement."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
