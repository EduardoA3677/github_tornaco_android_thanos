.class public abstract Llyiahf/vczjk/ec5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/iy0;
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x2L


# instance fields
.field protected final _base:Llyiahf/vczjk/w80;

.field protected final _mapperFeatures:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    sget-object v0, Llyiahf/vczjk/q94;->OooOOO:Llyiahf/vczjk/q94;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/fc5;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iput-object p1, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iput p2, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/w80;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iput p2, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    return-void
.end method

.method public static OooO0OO(Ljava/lang/Class;)I
    .locals 5

    invoke-virtual {p0}, Ljava/lang/Class;->getEnumConstants()[Ljava/lang/Object;

    move-result-object p0

    check-cast p0, [Ljava/lang/Enum;

    array-length v0, p0

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v1, v0, :cond_1

    aget-object v3, p0, v1

    check-cast v3, Llyiahf/vczjk/th1;

    invoke-interface {v3}, Llyiahf/vczjk/th1;->OooO00o()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-interface {v3}, Llyiahf/vczjk/th1;->OooO0O0()I

    move-result v3

    or-int/2addr v2, v3

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    return v2
.end method


# virtual methods
.method public abstract OooO(Ljava/lang/Class;)Llyiahf/vczjk/q94;
.end method

.method public final OooO0O0()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/gc5;->OooOoO0:Llyiahf/vczjk/gc5;

    iget v1, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v0

    return v0
.end method

.method public final OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_typeFactory:Llyiahf/vczjk/a4a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o()Llyiahf/vczjk/z50;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_defaultBase64:Llyiahf/vczjk/z50;

    return-object v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/yn;
    .locals 2

    sget-object v0, Llyiahf/vczjk/gc5;->OooOOO0:Llyiahf/vczjk/gc5;

    iget v1, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_annotationIntrospector:Llyiahf/vczjk/yn;

    return-object v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/m26;->OooOOO0:Llyiahf/vczjk/l26;

    return-object v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/jy0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_classIntrospector:Llyiahf/vczjk/jy0;

    return-object v0
.end method

.method public final OooO0oo()Ljava/text/DateFormat;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_dateFormat:Ljava/text/DateFormat;

    return-object v0
.end method

.method public final OooOO0()Llyiahf/vczjk/b5a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_typeResolverBuilder:Llyiahf/vczjk/b5a;

    return-object v0
.end method

.method public final OooOO0O()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method

.method public final OooOO0o()Ljava/util/Locale;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_locale:Ljava/util/Locale;

    return-object v0
.end method

.method public final OooOOO()Ljava/util/TimeZone;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_timeZone:Ljava/util/TimeZone;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/w80;->OooOOO0:Ljava/util/TimeZone;

    :cond_0
    return-object v0
.end method

.method public final OooOOO0()Llyiahf/vczjk/zy6;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_typeValidator:Llyiahf/vczjk/zy6;

    sget-object v1, Llyiahf/vczjk/qm4;->OooOOO0:Llyiahf/vczjk/qm4;

    if-ne v0, v1, :cond_0

    sget-object v1, Llyiahf/vczjk/gc5;->Oooo0o0:Llyiahf/vczjk/gc5;

    iget v2, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v0, Llyiahf/vczjk/i12;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    :cond_0
    return-object v0
.end method

.method public final OooOOOO()Llyiahf/vczjk/a4a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_typeFactory:Llyiahf/vczjk/a4a;

    return-object v0
.end method

.method public final OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/h90;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ec5;->OooOOo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOo()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/gc5;->OooOOO0:Llyiahf/vczjk/gc5;

    iget v1, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result v0

    return v0
.end method

.method public final OooOOo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ec5;->_base:Llyiahf/vczjk/w80;

    iget-object v0, v0, Llyiahf/vczjk/w80;->_classIntrospector:Llyiahf/vczjk/jy0;

    check-cast v0, Llyiahf/vczjk/l90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p0, p1}, Llyiahf/vczjk/l90;->OooO0O0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {p0, p1, p0}, Llyiahf/vczjk/l90;->OooO0OO(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/ec5;)Llyiahf/vczjk/hm;

    move-result-object v0

    invoke-static {p0, p1, v0}, Llyiahf/vczjk/h90;->OooO0o(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/hm;)Llyiahf/vczjk/h90;

    move-result-object p1

    return-object p1

    :cond_0
    return-object v0
.end method

.method public final OooOOoo(Llyiahf/vczjk/gc5;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ec5;->_mapperFeatures:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/gc5;->OooO0OO(I)Z

    move-result p1

    return p1
.end method
