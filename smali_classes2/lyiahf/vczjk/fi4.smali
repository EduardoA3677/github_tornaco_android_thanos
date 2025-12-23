.class public final Llyiahf/vczjk/fi4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ei4;


# static fields
.field public static final synthetic OooOOOo:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/wm7;

.field public final OooOOO0:Llyiahf/vczjk/t4a;

.field public final OooOOOO:Llyiahf/vczjk/gi4;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/fi4;

    const-string v2, "upperBounds"

    const-string v3, "getUpperBounds()Ljava/util/List;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/fi4;->OooOOOo:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/gi4;Llyiahf/vczjk/t4a;)V
    .locals 3

    const-string v0, "descriptor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/fi4;->OooOOO0:Llyiahf/vczjk/t4a;

    new-instance v0, Llyiahf/vczjk/o0oOOo;

    const/16 v1, 0x19

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/fi4;->OooOOO:Llyiahf/vczjk/wm7;

    if-nez p1, :cond_9

    invoke-interface {p2}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p1

    const-string p2, "getContainingDeclaration(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/by0;

    invoke-static {p1}, Llyiahf/vczjk/fi4;->OooO0o0(Llyiahf/vczjk/by0;)Llyiahf/vczjk/of4;

    move-result-object p1

    goto :goto_4

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/eo0;

    if-eqz v0, :cond_8

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/eo0;

    invoke-interface {v0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of p2, v0, Llyiahf/vczjk/by0;

    if-eqz p2, :cond_1

    check-cast v0, Llyiahf/vczjk/by0;

    invoke-static {v0}, Llyiahf/vczjk/fi4;->OooO0o0(Llyiahf/vczjk/by0;)Llyiahf/vczjk/of4;

    move-result-object p2

    goto :goto_3

    :cond_1
    instance-of p2, p1, Llyiahf/vczjk/m82;

    if-eqz p2, :cond_2

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/m82;

    goto :goto_0

    :cond_2
    move-object p2, v1

    :goto_0
    if-eqz p2, :cond_7

    invoke-interface {p2}, Llyiahf/vczjk/m82;->Ooooo0o()Llyiahf/vczjk/j82;

    move-result-object v0

    instance-of v2, v0, Llyiahf/vczjk/ce4;

    if-eqz v2, :cond_3

    check-cast v0, Llyiahf/vczjk/ce4;

    goto :goto_1

    :cond_3
    move-object v0, v1

    :goto_1
    if-eqz v0, :cond_4

    iget-object v0, v0, Llyiahf/vczjk/ce4;->OooOOOO:Llyiahf/vczjk/tm7;

    goto :goto_2

    :cond_4
    move-object v0, v1

    :goto_2
    instance-of v2, v0, Llyiahf/vczjk/tm7;

    if-eqz v2, :cond_5

    move-object v1, v0

    :cond_5
    if-eqz v1, :cond_6

    iget-object v0, v1, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    if-eqz v0, :cond_6

    invoke-static {v0}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/of4;

    :goto_3
    new-instance v0, Llyiahf/vczjk/tg7;

    invoke-direct {v0, p2}, Llyiahf/vczjk/tg7;-><init>(Llyiahf/vczjk/yf4;)V

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/v02;->OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    :goto_4
    check-cast p1, Llyiahf/vczjk/gi4;

    goto :goto_5

    :cond_6
    new-instance p1, Llyiahf/vczjk/es1;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Container of deserialized member is not resolved: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_7
    new-instance p2, Llyiahf/vczjk/es1;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Non-class callable descriptor must be deserialized: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_8
    new-instance p2, Llyiahf/vczjk/es1;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Unknown type parameter container: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_9
    :goto_5
    iput-object p1, p0, Llyiahf/vczjk/fi4;->OooOOOO:Llyiahf/vczjk/gi4;

    return-void
.end method

.method public static OooO0o0(Llyiahf/vczjk/by0;)Llyiahf/vczjk/of4;
    .locals 3

    invoke-static {p0}, Llyiahf/vczjk/mba;->OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    check-cast v0, Llyiahf/vczjk/of4;

    if-eqz v0, :cond_1

    return-object v0

    :cond_1
    new-instance v0, Llyiahf/vczjk/es1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Type parameter container is not resolved: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p0

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public final OooO0Oo()Ljava/lang/String;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fi4;->OooOOO0:Llyiahf/vczjk/t4a;

    invoke-interface {v0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "asString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/fi4;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/fi4;

    iget-object v0, p1, Llyiahf/vczjk/fi4;->OooOOOO:Llyiahf/vczjk/gi4;

    iget-object v1, p0, Llyiahf/vczjk/fi4;->OooOOOO:Llyiahf/vczjk/gi4;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/fi4;->OooO0Oo()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/fi4;->OooO0Oo()Ljava/lang/String;

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

    iget-object v0, p0, Llyiahf/vczjk/fi4;->OooOOOO:Llyiahf/vczjk/gi4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    invoke-virtual {p0}, Llyiahf/vczjk/fi4;->OooO0Oo()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/fi4;->OooOOO0:Llyiahf/vczjk/t4a;

    invoke-interface {v1}, Llyiahf/vczjk/t4a;->Oooo0OO()Llyiahf/vczjk/cda;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    sget-object v1, Llyiahf/vczjk/ji4;->OooOOOO:Llyiahf/vczjk/ji4;

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_1
    sget-object v1, Llyiahf/vczjk/ji4;->OooOOO:Llyiahf/vczjk/ji4;

    goto :goto_0

    :cond_2
    sget-object v1, Llyiahf/vczjk/ji4;->OooOOO0:Llyiahf/vczjk/ji4;

    :goto_0
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    if-eqz v1, :cond_5

    if-eq v1, v3, :cond_4

    if-ne v1, v2, :cond_3

    const-string v1, "out "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_3
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_4
    const-string v1, "in "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_5
    :goto_1
    invoke-virtual {p0}, Llyiahf/vczjk/fi4;->OooO0Oo()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
