.class public final Llyiahf/vczjk/kaa;
.super Llyiahf/vczjk/ib0;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _nameTransformer:Llyiahf/vczjk/wt5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/wt5;)V
    .locals 2

    iget-object v0, p1, Llyiahf/vczjk/ib0;->_props:[Llyiahf/vczjk/gb0;

    invoke-static {v0, p2}, Llyiahf/vczjk/ib0;->OooOOo([Llyiahf/vczjk/gb0;Llyiahf/vczjk/wt5;)[Llyiahf/vczjk/gb0;

    move-result-object v0

    iget-object v1, p1, Llyiahf/vczjk/ib0;->_filteredProps:[Llyiahf/vczjk/gb0;

    invoke-static {v1, p2}, Llyiahf/vczjk/ib0;->OooOOo([Llyiahf/vczjk/gb0;Llyiahf/vczjk/wt5;)[Llyiahf/vczjk/gb0;

    move-result-object v1

    invoke-direct {p0, p1, v0, v1}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;[Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)V

    iput-object p2, p0, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/kaa;Ljava/util/Set;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Ljava/util/Set;)V

    iget-object p1, p1, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    iput-object p1, p0, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/kaa;Llyiahf/vczjk/z66;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/z66;)V

    iget-object p1, p1, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    iput-object p1, p0, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/kaa;Llyiahf/vczjk/z66;Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/z66;Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    iput-object p1, p0, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/kaa;[Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;[Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)V

    iget-object p1, p1, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    iput-object p1, p0, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_objectIdWriter:Llyiahf/vczjk/z66;

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    invoke-virtual {p0, p1, p2, p3, v0}, Llyiahf/vczjk/ib0;->OooOOOO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Z)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ib0;->_propertyFilterId:Ljava/lang/Object;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/ib0;->OooOOoo(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_1
    invoke-virtual {p0, p3}, Llyiahf/vczjk/ib0;->OooOo00(Llyiahf/vczjk/tg8;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ig8;->OooOOo:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_2

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_objectIdWriter:Llyiahf/vczjk/z66;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ib0;->OooOOO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void

    :cond_0
    iget-object p4, p0, Llyiahf/vczjk/ib0;->_propertyFilterId:Ljava/lang/Object;

    if-nez p4, :cond_1

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/ib0;->OooOOoo(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_1
    invoke-virtual {p0, p3}, Llyiahf/vczjk/ib0;->OooOo00(Llyiahf/vczjk/tg8;)V

    throw v1

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/b59;->OooO0OO()Ljava/lang/Class;

    move-result-object p1

    const-string p2, "Unwrapped property requires use of type information: cannot serialize without disabling `SerializationFeature.FAIL_ON_UNWRAPPED_TYPE_IDENTIFIERS`"

    invoke-virtual {p3, p1, p2}, Llyiahf/vczjk/mc4;->o000oOoO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    throw v1
.end method

.method public final OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;
    .locals 1

    new-instance v0, Llyiahf/vczjk/kaa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/kaa;-><init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/wt5;)V

    return-object v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ib0;
    .locals 0

    return-object p0
.end method

.method public final OooOo([Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)Llyiahf/vczjk/ib0;
    .locals 1

    new-instance v0, Llyiahf/vczjk/kaa;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/kaa;-><init>(Llyiahf/vczjk/kaa;[Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)V

    return-object v0
.end method

.method public final OooOo0(Ljava/lang/Object;)Llyiahf/vczjk/ib0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/kaa;

    iget-object v1, p0, Llyiahf/vczjk/ib0;->_objectIdWriter:Llyiahf/vczjk/z66;

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/kaa;-><init>(Llyiahf/vczjk/kaa;Llyiahf/vczjk/z66;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooOo0O(Ljava/util/Set;)Llyiahf/vczjk/ib0;
    .locals 1

    new-instance v0, Llyiahf/vczjk/kaa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/kaa;-><init>(Llyiahf/vczjk/kaa;Ljava/util/Set;)V

    return-object v0
.end method

.method public final OooOo0o(Llyiahf/vczjk/z66;)Llyiahf/vczjk/ib0;
    .locals 1

    new-instance v0, Llyiahf/vczjk/kaa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/kaa;-><init>(Llyiahf/vczjk/kaa;Llyiahf/vczjk/z66;)V

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/b59;->OooO0OO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "UnwrappingBeanSerializer for "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
