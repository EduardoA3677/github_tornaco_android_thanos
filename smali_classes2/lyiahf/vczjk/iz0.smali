.class public final Llyiahf/vczjk/iz0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/jz0;


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/iz0;

.field public static final OooO0OO:Llyiahf/vczjk/iz0;

.field public static final OooO0Oo:Llyiahf/vczjk/iz0;


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/iz0;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/iz0;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/iz0;->OooO0O0:Llyiahf/vczjk/iz0;

    new-instance v0, Llyiahf/vczjk/iz0;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/iz0;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/iz0;->OooO0OO:Llyiahf/vczjk/iz0;

    new-instance v0, Llyiahf/vczjk/iz0;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/iz0;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/iz0;->OooO0Oo:Llyiahf/vczjk/iz0;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/iz0;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/gz0;)Ljava/lang/String;
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    const-string v1, "getName(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/xt6;->Oooo000(Llyiahf/vczjk/qt5;)Ljava/lang/String;

    move-result-object v0

    instance-of v1, p0, Llyiahf/vczjk/t4a;

    if-eqz v1, :cond_0

    goto :goto_1

    :cond_0
    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p0

    const-string v1, "getContainingDeclaration(...)"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v1, p0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_1

    check-cast p0, Llyiahf/vczjk/gz0;

    invoke-static {p0}, Llyiahf/vczjk/iz0;->OooO0O0(Llyiahf/vczjk/gz0;)Ljava/lang/String;

    move-result-object p0

    goto :goto_0

    :cond_1
    instance-of v1, p0, Llyiahf/vczjk/hh6;

    if-eqz v1, :cond_2

    check-cast p0, Llyiahf/vczjk/hh6;

    check-cast p0, Llyiahf/vczjk/ih6;

    iget-object p0, p0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    iget-object p0, p0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    const-string v1, "<this>"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/ic3;->OooO0o0(Llyiahf/vczjk/ic3;)Ljava/util/List;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/xt6;->Oooo00O(Ljava/util/List;)Ljava/lang/String;

    move-result-object p0

    goto :goto_0

    :cond_2
    const/4 p0, 0x0

    :goto_0
    if-eqz p0, :cond_3

    const-string v1, ""

    invoke-virtual {p0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p0, 0x2e

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_3
    :goto_1
    return-object v0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/gz0;Llyiahf/vczjk/h72;)Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/iz0;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "renderer"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/iz0;->OooO0O0(Llyiahf/vczjk/gz0;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_0
    const-string v0, "renderer"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/t4a;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/t4a;

    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p1

    const-string v0, "getName(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/h72;->Oooo0oo(Llyiahf/vczjk/qt5;Z)Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    :cond_1
    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p2

    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-interface {p1}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p1

    instance-of p2, p1, Llyiahf/vczjk/by0;

    if-nez p2, :cond_1

    new-instance p1, Llyiahf/vczjk/it7;

    invoke-direct {p1, v0}, Llyiahf/vczjk/it7;-><init>(Ljava/util/ArrayList;)V

    invoke-static {p1}, Llyiahf/vczjk/xt6;->Oooo00O(Ljava/util/List;)Ljava/lang/String;

    move-result-object p1

    :goto_0
    return-object p1

    :pswitch_1
    const-string v0, "renderer"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/t4a;

    if-eqz v0, :cond_2

    check-cast p1, Llyiahf/vczjk/t4a;

    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p1

    const-string v0, "getName(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/h72;->Oooo0oo(Llyiahf/vczjk/qt5;Z)Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p1

    const-string v0, "getFqName(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/ic3;->OooO0o0(Llyiahf/vczjk/ic3;)Ljava/util/List;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/xt6;->Oooo00O(Ljava/util/List;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/h72;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    :goto_1
    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
