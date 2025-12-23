.class public abstract Llyiahf/vczjk/fc5;
.super Llyiahf/vczjk/ec5;
.source "SourceFile"


# static fields
.field public static final OooOOO:I

.field public static final OooOOO0:I


# instance fields
.field protected final _attributes:Llyiahf/vczjk/jn1;

.field protected final _configOverrides:Llyiahf/vczjk/vh1;

.field protected final _mixIns:Llyiahf/vczjk/ro8;

.field protected final _rootName:Llyiahf/vczjk/xa7;

.field protected final _rootNames:Llyiahf/vczjk/cv7;

.field protected final _subtypeResolver:Llyiahf/vczjk/k99;

.field protected final _view:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-class v0, Llyiahf/vczjk/gc5;

    invoke-static {v0}, Llyiahf/vczjk/ec5;->OooO0OO(Ljava/lang/Class;)I

    move-result v0

    sput v0, Llyiahf/vczjk/fc5;->OooOOO0:I

    sget-object v0, Llyiahf/vczjk/gc5;->OooOOo0:Llyiahf/vczjk/gc5;

    invoke-virtual {v0}, Llyiahf/vczjk/gc5;->OooO0O0()I

    move-result v0

    sget-object v1, Llyiahf/vczjk/gc5;->OooOOo:Llyiahf/vczjk/gc5;

    invoke-virtual {v1}, Llyiahf/vczjk/gc5;->OooO0O0()I

    move-result v1

    or-int/2addr v0, v1

    sget-object v1, Llyiahf/vczjk/gc5;->OooOOoo:Llyiahf/vczjk/gc5;

    invoke-virtual {v1}, Llyiahf/vczjk/gc5;->OooO0O0()I

    move-result v1

    or-int/2addr v0, v1

    sget-object v1, Llyiahf/vczjk/gc5;->OooOo00:Llyiahf/vczjk/gc5;

    invoke-virtual {v1}, Llyiahf/vczjk/gc5;->OooO0O0()I

    move-result v1

    or-int/2addr v0, v1

    sget-object v1, Llyiahf/vczjk/gc5;->OooOOOo:Llyiahf/vczjk/gc5;

    invoke-virtual {v1}, Llyiahf/vczjk/gc5;->OooO0O0()I

    move-result v1

    or-int/2addr v0, v1

    sput v0, Llyiahf/vczjk/fc5;->OooOOO:I

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/fc5;I)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ec5;-><init>(Llyiahf/vczjk/fc5;I)V

    iget-object p2, p1, Llyiahf/vczjk/fc5;->_mixIns:Llyiahf/vczjk/ro8;

    iput-object p2, p0, Llyiahf/vczjk/fc5;->_mixIns:Llyiahf/vczjk/ro8;

    iget-object p2, p1, Llyiahf/vczjk/fc5;->_subtypeResolver:Llyiahf/vczjk/k99;

    iput-object p2, p0, Llyiahf/vczjk/fc5;->_subtypeResolver:Llyiahf/vczjk/k99;

    iget-object p2, p1, Llyiahf/vczjk/fc5;->_rootNames:Llyiahf/vczjk/cv7;

    iput-object p2, p0, Llyiahf/vczjk/fc5;->_rootNames:Llyiahf/vczjk/cv7;

    iget-object p2, p1, Llyiahf/vczjk/fc5;->_rootName:Llyiahf/vczjk/xa7;

    iput-object p2, p0, Llyiahf/vczjk/fc5;->_rootName:Llyiahf/vczjk/xa7;

    iget-object p2, p1, Llyiahf/vczjk/fc5;->_view:Ljava/lang/Class;

    iput-object p2, p0, Llyiahf/vczjk/fc5;->_view:Ljava/lang/Class;

    iget-object p2, p1, Llyiahf/vczjk/fc5;->_attributes:Llyiahf/vczjk/jn1;

    iput-object p2, p0, Llyiahf/vczjk/fc5;->_attributes:Llyiahf/vczjk/jn1;

    iget-object p1, p1, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iput-object p1, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/w80;Llyiahf/vczjk/k99;Llyiahf/vczjk/ro8;Llyiahf/vczjk/cv7;Llyiahf/vczjk/vh1;)V
    .locals 1

    sget v0, Llyiahf/vczjk/fc5;->OooOOO0:I

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/ec5;-><init>(Llyiahf/vczjk/w80;I)V

    iput-object p3, p0, Llyiahf/vczjk/fc5;->_mixIns:Llyiahf/vczjk/ro8;

    iput-object p2, p0, Llyiahf/vczjk/fc5;->_subtypeResolver:Llyiahf/vczjk/k99;

    iput-object p4, p0, Llyiahf/vczjk/fc5;->_rootNames:Llyiahf/vczjk/cv7;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/fc5;->_rootName:Llyiahf/vczjk/xa7;

    iput-object p1, p0, Llyiahf/vczjk/fc5;->_view:Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/in1;->OooOOO:Llyiahf/vczjk/in1;

    iput-object p1, p0, Llyiahf/vczjk/fc5;->_attributes:Llyiahf/vczjk/jn1;

    iput-object p5, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Class;)Llyiahf/vczjk/q94;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object v1, v0, Llyiahf/vczjk/vh1;->_overrides:Ljava/util/Map;

    if-eqz v1, :cond_0

    invoke-interface {v1, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uh1;

    :cond_0
    iget-object v8, v0, Llyiahf/vczjk/vh1;->_defaultLeniency:Ljava/lang/Boolean;

    if-nez v8, :cond_1

    sget-object p1, Llyiahf/vczjk/q94;->OooOOO:Llyiahf/vczjk/q94;

    return-object p1

    :cond_1
    new-instance v1, Llyiahf/vczjk/q94;

    sget-object v7, Llyiahf/vczjk/o94;->OooO0OO:Llyiahf/vczjk/o94;

    const/4 v3, 0x0

    const/4 v4, 0x0

    const-string v2, ""

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/q94;-><init>(Ljava/lang/String;Llyiahf/vczjk/p94;Ljava/util/Locale;Ljava/lang/String;Ljava/util/TimeZone;Llyiahf/vczjk/o94;Ljava/lang/Boolean;)V

    return-object v1
.end method

.method public final OooO00o(Ljava/lang/Class;)Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_mixIns:Llyiahf/vczjk/ro8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ro8;->OooO00o(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object v0, v0, Llyiahf/vczjk/vh1;->_overrides:Ljava/util/Map;

    if-nez v0, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uh1;

    :goto_0
    if-nez p1, :cond_1

    sget-object p1, Llyiahf/vczjk/uh1;->OooO00o:Llyiahf/vczjk/uh1;

    :cond_1
    return-object p1
.end method

.method public final OooOo0(Ljava/lang/Class;)Llyiahf/vczjk/xa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_rootName:Llyiahf/vczjk/xa7;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/fc5;->_rootNames:Llyiahf/vczjk/cv7;

    invoke-virtual {v0, p1, p0}, Llyiahf/vczjk/cv7;->OooO00o(Ljava/lang/Class;Llyiahf/vczjk/fc5;)Llyiahf/vczjk/xa7;

    move-result-object p1

    return-object p1
.end method

.method public abstract OooOo00(I)Llyiahf/vczjk/fc5;
.end method

.method public final OooOo0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/xa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_rootName:Llyiahf/vczjk/xa7;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/fc5;->_rootNames:Llyiahf/vczjk/cv7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {v0, p1, p0}, Llyiahf/vczjk/cv7;->OooO00o(Ljava/lang/Class;Llyiahf/vczjk/fc5;)Llyiahf/vczjk/xa7;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo0o()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_view:Ljava/lang/Class;

    return-object v0
.end method

.method public final OooOoO(Ljava/lang/Class;)Llyiahf/vczjk/fa4;
    .locals 1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/fc5;->OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;

    iget-object p1, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object p1, p1, Llyiahf/vczjk/vh1;->_defaultInclusion:Llyiahf/vczjk/fa4;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    invoke-virtual {p1, v0}, Llyiahf/vczjk/fa4;->OooO0Oo(Llyiahf/vczjk/fa4;)Llyiahf/vczjk/fa4;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO0(Ljava/lang/Class;Llyiahf/vczjk/hm;)Llyiahf/vczjk/ba4;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    move-object p2, v1

    goto :goto_0

    :cond_0
    invoke-virtual {v0, p2}, Llyiahf/vczjk/yn;->Oooo00o(Llyiahf/vczjk/u34;)Llyiahf/vczjk/ba4;

    move-result-object p2

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object v0, v0, Llyiahf/vczjk/vh1;->_overrides:Ljava/util/Map;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uh1;

    :goto_1
    sget-object p1, Llyiahf/vczjk/ba4;->OooOOO0:Llyiahf/vczjk/ba4;

    if-nez p2, :cond_2

    return-object v1

    :cond_2
    return-object p2
.end method

.method public final OooOoOO()Llyiahf/vczjk/fa4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object v0, v0, Llyiahf/vczjk/vh1;->_defaultInclusion:Llyiahf/vczjk/fa4;

    return-object v0
.end method

.method public final OooOoo(Ljava/lang/Class;Llyiahf/vczjk/hm;)Llyiahf/vczjk/gka;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object v0, v0, Llyiahf/vczjk/vh1;->_visibilityChecker:Llyiahf/vczjk/gka;

    iget v1, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    sget v2, Llyiahf/vczjk/fc5;->OooOOO:I

    and-int v3, v1, v2

    if-eq v3, v2, :cond_9

    sget-object v2, Llyiahf/vczjk/gc5;->OooOOo0:Llyiahf/vczjk/gc5;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v1

    if-nez v1, :cond_1

    check-cast v0, Llyiahf/vczjk/fka;

    sget-object v6, Llyiahf/vczjk/x84;->OooOOOO:Llyiahf/vczjk/x84;

    iget-object v1, v0, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    if-ne v1, v6, :cond_0

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/fka;

    iget-object v2, v0, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    iget-object v3, v0, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    iget-object v4, v0, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    iget-object v5, v0, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/fka;-><init>(Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;)V

    move-object v0, v1

    :cond_1
    :goto_0
    sget-object v1, Llyiahf/vczjk/gc5;->OooOOo:Llyiahf/vczjk/gc5;

    iget v2, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v1

    if-nez v1, :cond_3

    check-cast v0, Llyiahf/vczjk/fka;

    sget-object v2, Llyiahf/vczjk/x84;->OooOOOO:Llyiahf/vczjk/x84;

    iget-object v1, v0, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    if-ne v1, v2, :cond_2

    goto :goto_1

    :cond_2
    new-instance v1, Llyiahf/vczjk/fka;

    iget-object v3, v0, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    iget-object v4, v0, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    iget-object v5, v0, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    iget-object v6, v0, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/fka;-><init>(Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;)V

    move-object v0, v1

    :cond_3
    :goto_1
    sget-object v1, Llyiahf/vczjk/gc5;->OooOOoo:Llyiahf/vczjk/gc5;

    iget v2, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v1

    if-nez v1, :cond_5

    check-cast v0, Llyiahf/vczjk/fka;

    sget-object v3, Llyiahf/vczjk/x84;->OooOOOO:Llyiahf/vczjk/x84;

    iget-object v1, v0, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    if-ne v1, v3, :cond_4

    goto :goto_2

    :cond_4
    new-instance v1, Llyiahf/vczjk/fka;

    iget-object v2, v0, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    iget-object v4, v0, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    iget-object v5, v0, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    iget-object v6, v0, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/fka;-><init>(Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;)V

    move-object v0, v1

    :cond_5
    :goto_2
    sget-object v1, Llyiahf/vczjk/gc5;->OooOo00:Llyiahf/vczjk/gc5;

    iget v2, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v1

    if-nez v1, :cond_7

    check-cast v0, Llyiahf/vczjk/fka;

    sget-object v4, Llyiahf/vczjk/x84;->OooOOOO:Llyiahf/vczjk/x84;

    iget-object v1, v0, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    if-ne v1, v4, :cond_6

    goto :goto_3

    :cond_6
    new-instance v1, Llyiahf/vczjk/fka;

    iget-object v2, v0, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    iget-object v3, v0, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    iget-object v5, v0, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    iget-object v6, v0, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/fka;-><init>(Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;)V

    move-object v0, v1

    :cond_7
    :goto_3
    sget-object v1, Llyiahf/vczjk/gc5;->OooOOOo:Llyiahf/vczjk/gc5;

    iget v2, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v1

    if-nez v1, :cond_9

    check-cast v0, Llyiahf/vczjk/fka;

    sget-object v5, Llyiahf/vczjk/x84;->OooOOOO:Llyiahf/vczjk/x84;

    iget-object v1, v0, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    if-ne v1, v5, :cond_8

    goto :goto_4

    :cond_8
    new-instance v1, Llyiahf/vczjk/fka;

    iget-object v2, v0, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    iget-object v3, v0, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    iget-object v4, v0, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    iget-object v6, v0, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/fka;-><init>(Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;)V

    move-object v0, v1

    :cond_9
    :goto_4
    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v1

    if-eqz v1, :cond_a

    invoke-virtual {v1, p2, v0}, Llyiahf/vczjk/yn;->OooO0O0(Llyiahf/vczjk/hm;Llyiahf/vczjk/gka;)Llyiahf/vczjk/gka;

    move-result-object v0

    :cond_a
    iget-object p2, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object p2, p2, Llyiahf/vczjk/vh1;->_overrides:Ljava/util/Map;

    if-nez p2, :cond_b

    const/4 p1, 0x0

    goto :goto_5

    :cond_b
    invoke-interface {p2, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uh1;

    :goto_5
    if-eqz p1, :cond_c

    check-cast v0, Llyiahf/vczjk/fka;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_c
    return-object v0
.end method

.method public final OooOoo0()Llyiahf/vczjk/ac4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object v0, v0, Llyiahf/vczjk/vh1;->_defaultSetterInfo:Llyiahf/vczjk/ac4;

    return-object v0
.end method

.method public final OooOooO()Llyiahf/vczjk/xa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_rootName:Llyiahf/vczjk/xa7;

    return-object v0
.end method

.method public final OooOooo()Llyiahf/vczjk/k99;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_subtypeResolver:Llyiahf/vczjk/k99;

    return-object v0
.end method

.method public final varargs Oooo000([Llyiahf/vczjk/gc5;)Llyiahf/vczjk/fc5;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    array-length v1, p1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    aget-object v3, p1, v2

    invoke-virtual {v3}, Llyiahf/vczjk/gc5;->OooO0O0()I

    move-result v3

    not-int v3, v3

    and-int/2addr v0, v3

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    iget p1, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    if-ne v0, p1, :cond_1

    return-object p0

    :cond_1
    invoke-virtual {p0, v0}, Llyiahf/vczjk/fc5;->OooOo00(I)Llyiahf/vczjk/fc5;

    move-result-object p1

    return-object p1
.end method
