.class public final Llyiahf/vczjk/z2a;
.super Llyiahf/vczjk/tf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/y2a;


# static fields
.field public static final o000oOoO:Llyiahf/vczjk/sp3;


# instance fields
.field public final OoooO:Llyiahf/vczjk/a3a;

.field public final OoooO0O:Llyiahf/vczjk/w59;

.field public OoooOO0:Llyiahf/vczjk/ux0;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/z2a;

    const-string v2, "withDispatchReceiver"

    const-string v3, "getWithDispatchReceiver()Lorg/jetbrains/kotlin/descriptors/impl/TypeAliasConstructorDescriptor;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    new-instance v0, Llyiahf/vczjk/sp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/z2a;->o000oOoO:Llyiahf/vczjk/sp3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/w59;Llyiahf/vczjk/a3a;Llyiahf/vczjk/ux0;Llyiahf/vczjk/y2a;Llyiahf/vczjk/ko;ILlyiahf/vczjk/sx8;)V
    .locals 7

    sget-object v5, Llyiahf/vczjk/vy8;->OooO0o0:Llyiahf/vczjk/qt5;

    move-object v0, p0

    move-object v3, p2

    move-object v4, p4

    move-object v2, p5

    move v1, p6

    move-object v6, p7

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/tf3;-><init>(ILlyiahf/vczjk/ko;Llyiahf/vczjk/v02;Llyiahf/vczjk/rf3;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)V

    iput-object p1, v0, Llyiahf/vczjk/z2a;->OoooO0O:Llyiahf/vczjk/w59;

    iput-object v3, v0, Llyiahf/vczjk/z2a;->OoooO:Llyiahf/vczjk/a3a;

    new-instance p2, Llyiahf/vczjk/o0O000;

    const/16 p4, 0x1c

    const/4 p5, 0x0

    invoke-direct {p2, p4, p0, p3, p5}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    check-cast p1, Llyiahf/vczjk/q45;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p4, Llyiahf/vczjk/n45;

    invoke-direct {p4, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p3, v0, Llyiahf/vczjk/z2a;->OoooOO0:Llyiahf/vczjk/ux0;

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO00o()Llyiahf/vczjk/co0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/z2a;->o0000o0()Llyiahf/vczjk/y2a;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO00o()Llyiahf/vczjk/eo0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/z2a;->o0000o0()Llyiahf/vczjk/y2a;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO00o()Llyiahf/vczjk/rf3;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/z2a;->o0000o0()Llyiahf/vczjk/y2a;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO00o()Llyiahf/vczjk/v02;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/z2a;->o0000o0()Llyiahf/vczjk/y2a;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/rf3;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/z2a;->o0000o0O(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/z2a;

    move-result-object p1

    return-object p1
.end method

.method public final bridge synthetic OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/x02;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/z2a;->o0000o0O(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/z2a;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0o()Llyiahf/vczjk/hz0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z2a;->OoooO:Llyiahf/vczjk/a3a;

    return-object v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/v02;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z2a;->OoooO:Llyiahf/vczjk/a3a;

    return-object v0
.end method

.method public final OooOOoo()Llyiahf/vczjk/uk4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooOoOO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z2a;->OoooOO0:Llyiahf/vczjk/ux0;

    iget-boolean v0, v0, Llyiahf/vczjk/ux0;->OoooO0O:Z

    return v0
.end method

.method public final OooOoo0()Llyiahf/vczjk/by0;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/z2a;->OoooOO0:Llyiahf/vczjk/ux0;

    invoke-virtual {v0}, Llyiahf/vczjk/ux0;->OooOoo0()Llyiahf/vczjk/by0;

    move-result-object v0

    const-string v1, "getConstructedClass(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooooOo(Llyiahf/vczjk/by0;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;)Llyiahf/vczjk/eo0;
    .locals 2

    const-string v0, "newOwner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "visibility"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "kind"

    const/4 v1, 0x2

    invoke-static {v1, v0}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/i5a;->OooO0O0:Llyiahf/vczjk/i5a;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/tf3;->o0000OOO(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/sf3;

    move-result-object v0

    iput-object p1, v0, Llyiahf/vczjk/sf3;->OooOOO:Llyiahf/vczjk/v02;

    iput-object p2, v0, Llyiahf/vczjk/sf3;->OooOOOO:Llyiahf/vczjk/yk5;

    iput-object p3, v0, Llyiahf/vczjk/sf3;->OooOOOo:Llyiahf/vczjk/q72;

    iput v1, v0, Llyiahf/vczjk/sf3;->OooOOo:I

    const/4 p1, 0x0

    iput-boolean p1, v0, Llyiahf/vczjk/sf3;->OooOoO0:Z

    iget-object p1, v0, Llyiahf/vczjk/sf3;->Oooo0O0:Llyiahf/vczjk/tf3;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/tf3;->o0000O(Llyiahf/vczjk/sf3;)Llyiahf/vczjk/tf3;

    move-result-object p1

    const-string p2, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.impl.TypeAliasConstructorDescriptor"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/y2a;

    return-object p1
.end method

.method public final o0000o0()Llyiahf/vczjk/y2a;
    .locals 2

    invoke-super {p0}, Llyiahf/vczjk/tf3;->OooO00o()Llyiahf/vczjk/rf3;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.impl.TypeAliasConstructorDescriptor"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/y2a;

    return-object v0
.end method

.method public final o0000o0O(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/z2a;
    .locals 2

    const-string v0, "substitutor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-super {p0, p1}, Llyiahf/vczjk/tf3;->OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/rf3;

    move-result-object p1

    const-string v0, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.impl.TypeAliasConstructorDescriptorImpl"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/z2a;

    iget-object v0, p1, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/i5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/i5a;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/z2a;->OoooOO0:Llyiahf/vczjk/ux0;

    invoke-virtual {v1}, Llyiahf/vczjk/ux0;->o0000o0o()Llyiahf/vczjk/ux0;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ux0;->o0000oOO(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/ux0;

    move-result-object v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iput-object v0, p1, Llyiahf/vczjk/z2a;->OoooOO0:Llyiahf/vczjk/ux0;

    return-object p1
.end method

.method public final bridge synthetic o0000oO()Llyiahf/vczjk/x02;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/z2a;->o0000o0()Llyiahf/vczjk/y2a;

    move-result-object v0

    return-object v0
.end method

.method public final o000OO(ILlyiahf/vczjk/ko;Llyiahf/vczjk/v02;Llyiahf/vczjk/rf3;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/tf3;
    .locals 8

    const-string p4, "newOwner"

    invoke-static {p3, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "kind"

    invoke-static {p1, p3}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    const-string p3, "annotations"

    invoke-static {p2, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v6, 0x1

    if-eq p1, v6, :cond_0

    const/4 p3, 0x4

    :cond_0
    new-instance v0, Llyiahf/vczjk/z2a;

    iget-object v3, p0, Llyiahf/vczjk/z2a;->OoooOO0:Llyiahf/vczjk/ux0;

    iget-object v1, p0, Llyiahf/vczjk/z2a;->OoooO0O:Llyiahf/vczjk/w59;

    iget-object v2, p0, Llyiahf/vczjk/z2a;->OoooO:Llyiahf/vczjk/a3a;

    move-object v4, p0

    move-object v5, p2

    move-object v7, p6

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/z2a;-><init>(Llyiahf/vczjk/w59;Llyiahf/vczjk/a3a;Llyiahf/vczjk/ux0;Llyiahf/vczjk/y2a;Llyiahf/vczjk/ko;ILlyiahf/vczjk/sx8;)V

    return-object v0
.end method
