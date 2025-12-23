.class public final Llyiahf/vczjk/gg8;
.super Llyiahf/vczjk/fc5;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/j32;

.field public static final OooOOOo:I

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _defaultPrettyPrinter:Llyiahf/vczjk/u37;

.field protected final _filterProvider:Llyiahf/vczjk/x03;

.field protected final _formatWriteFeatures:I

.field protected final _formatWriteFeaturesToChange:I

.field protected final _generatorFeatures:I

.field protected final _generatorFeaturesToChange:I

.field protected final _serFeatures:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/j32;

    invoke-direct {v0}, Llyiahf/vczjk/j32;-><init>()V

    sput-object v0, Llyiahf/vczjk/gg8;->OooOOOO:Llyiahf/vczjk/j32;

    const-class v0, Llyiahf/vczjk/ig8;

    invoke-static {v0}, Llyiahf/vczjk/ec5;->OooO0OO(Ljava/lang/Class;)I

    move-result v0

    sput v0, Llyiahf/vczjk/gg8;->OooOOOo:I

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/gg8;IIIIII)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/fc5;-><init>(Llyiahf/vczjk/fc5;I)V

    iput p3, p0, Llyiahf/vczjk/gg8;->_serFeatures:I

    iget-object p1, p1, Llyiahf/vczjk/gg8;->_defaultPrettyPrinter:Llyiahf/vczjk/u37;

    iput-object p1, p0, Llyiahf/vczjk/gg8;->_defaultPrettyPrinter:Llyiahf/vczjk/u37;

    iput p4, p0, Llyiahf/vczjk/gg8;->_generatorFeatures:I

    iput p5, p0, Llyiahf/vczjk/gg8;->_generatorFeaturesToChange:I

    iput p6, p0, Llyiahf/vczjk/gg8;->_formatWriteFeatures:I

    iput p7, p0, Llyiahf/vczjk/gg8;->_formatWriteFeaturesToChange:I

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/w80;Llyiahf/vczjk/k99;Llyiahf/vczjk/ro8;Llyiahf/vczjk/cv7;Llyiahf/vczjk/vh1;)V
    .locals 0

    invoke-direct/range {p0 .. p5}, Llyiahf/vczjk/fc5;-><init>(Llyiahf/vczjk/w80;Llyiahf/vczjk/k99;Llyiahf/vczjk/ro8;Llyiahf/vczjk/cv7;Llyiahf/vczjk/vh1;)V

    move-object p1, p0

    sget p2, Llyiahf/vczjk/gg8;->OooOOOo:I

    iput p2, p1, Llyiahf/vczjk/gg8;->_serFeatures:I

    sget-object p2, Llyiahf/vczjk/gg8;->OooOOOO:Llyiahf/vczjk/j32;

    iput-object p2, p1, Llyiahf/vczjk/gg8;->_defaultPrettyPrinter:Llyiahf/vczjk/u37;

    const/4 p2, 0x0

    iput p2, p1, Llyiahf/vczjk/gg8;->_generatorFeatures:I

    iput p2, p1, Llyiahf/vczjk/gg8;->_generatorFeaturesToChange:I

    iput p2, p1, Llyiahf/vczjk/gg8;->_formatWriteFeatures:I

    iput p2, p1, Llyiahf/vczjk/gg8;->_formatWriteFeaturesToChange:I

    return-void
.end method


# virtual methods
.method public final OooOo00(I)Llyiahf/vczjk/fc5;
    .locals 8

    new-instance v0, Llyiahf/vczjk/gg8;

    iget v3, p0, Llyiahf/vczjk/gg8;->_serFeatures:I

    iget v4, p0, Llyiahf/vczjk/gg8;->_generatorFeatures:I

    iget v5, p0, Llyiahf/vczjk/gg8;->_generatorFeaturesToChange:I

    iget v6, p0, Llyiahf/vczjk/gg8;->_formatWriteFeatures:I

    iget v7, p0, Llyiahf/vczjk/gg8;->_formatWriteFeaturesToChange:I

    move-object v1, p0

    move v2, p1

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/gg8;-><init>(Llyiahf/vczjk/gg8;IIIIII)V

    return-object v0
.end method

.method public final Oooo0(Llyiahf/vczjk/ig8;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/gg8;->_serFeatures:I

    invoke-virtual {p1}, Llyiahf/vczjk/ig8;->OooO0O0()I

    move-result p1

    and-int/2addr p1, v0

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final Oooo00O(Llyiahf/vczjk/u94;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/ig8;->OooOOO:Llyiahf/vczjk/ig8;

    iget v1, p0, Llyiahf/vczjk/gg8;->_serFeatures:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ig8;->OooO0OO(I)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, p1, Llyiahf/vczjk/u94;->OooOOO0:Llyiahf/vczjk/u37;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/gg8;->_defaultPrettyPrinter:Llyiahf/vczjk/u37;

    instance-of v1, v0, Llyiahf/vczjk/l14;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/l14;

    check-cast v0, Llyiahf/vczjk/j32;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/j32;

    invoke-direct {v1, v0}, Llyiahf/vczjk/j32;-><init>(Llyiahf/vczjk/j32;)V

    move-object v0, v1

    :cond_0
    if-eqz v0, :cond_1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->Oooooo0(Llyiahf/vczjk/u37;)V

    :cond_1
    sget-object v0, Llyiahf/vczjk/ig8;->OooOooo:Llyiahf/vczjk/ig8;

    iget v1, p0, Llyiahf/vczjk/gg8;->_serFeatures:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ig8;->OooO0OO(I)Z

    move-result v0

    iget v1, p0, Llyiahf/vczjk/gg8;->_generatorFeaturesToChange:I

    if-nez v1, :cond_2

    if-eqz v0, :cond_4

    :cond_2
    iget v2, p0, Llyiahf/vczjk/gg8;->_generatorFeatures:I

    if-eqz v0, :cond_3

    sget-object v0, Llyiahf/vczjk/t94;->OooOo00:Llyiahf/vczjk/t94;

    invoke-virtual {v0}, Llyiahf/vczjk/t94;->OooO0OO()I

    move-result v0

    or-int/2addr v2, v0

    or-int/2addr v1, v0

    :cond_3
    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/u94;->OoooO00(II)Llyiahf/vczjk/u94;

    :cond_4
    iget v0, p0, Llyiahf/vczjk/gg8;->_formatWriteFeaturesToChange:I

    if-eqz v0, :cond_5

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_5
    return-void
.end method

.method public final Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;
    .locals 7

    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooO0oO()Llyiahf/vczjk/jy0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/l90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p0, p1}, Llyiahf/vczjk/l90;->OooO0O0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/l90;->OooO00o(Llyiahf/vczjk/fc5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {p0, p1, p0}, Llyiahf/vczjk/l90;->OooO0OO(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/ec5;)Llyiahf/vczjk/hm;

    move-result-object v5

    new-instance v1, Llyiahf/vczjk/yg6;

    const-string v6, "set"

    const/4 v3, 0x1

    move-object v2, p0

    move-object v4, p1

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/yg6;-><init>(Llyiahf/vczjk/fc5;ZLlyiahf/vczjk/x64;Llyiahf/vczjk/hm;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/h90;

    invoke-direct {p1, v1}, Llyiahf/vczjk/h90;-><init>(Llyiahf/vczjk/yg6;)V

    return-object p1

    :cond_0
    return-object v0
.end method
