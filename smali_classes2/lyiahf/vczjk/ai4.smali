.class public abstract Llyiahf/vczjk/ai4;
.super Llyiahf/vczjk/ff4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/th4;


# static fields
.field public static final OooOo0:Ljava/lang/Object;


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/yf4;

.field public final OooOOOo:Ljava/lang/String;

.field public final OooOOo:Ljava/lang/Object;

.field public final OooOOo0:Ljava/lang/String;

.field public final OooOOoo:Ljava/lang/Object;

.field public final OooOo00:Llyiahf/vczjk/wm7;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/ai4;->OooOo0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 7

    const-string v0, "container"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "signature"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v6, p4

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/ai4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/ua7;Ljava/lang/Object;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/ua7;Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/ff4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ai4;->OooOOOO:Llyiahf/vczjk/yf4;

    iput-object p2, p0, Llyiahf/vczjk/ai4;->OooOOOo:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/ai4;->OooOOo0:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/ai4;->OooOOo:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance p2, Llyiahf/vczjk/uh4;

    const/4 p3, 0x0

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/uh4;-><init>(Llyiahf/vczjk/ai4;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ai4;->OooOOoo:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/uh4;

    const/4 p2, 0x1

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/uh4;-><init>(Llyiahf/vczjk/ai4;I)V

    invoke-static {p4, p1}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ai4;->OooOo00:Llyiahf/vczjk/wm7;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V
    .locals 7

    const-string v0, "container"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "descriptor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v3

    const-string v0, "asString(...)"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2}, Llyiahf/vczjk/iz7;->OooO0O0(Llyiahf/vczjk/sa7;)Llyiahf/vczjk/t51;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/t51;->OooOOO()Ljava/lang/String;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/fo0;->OooOOO0:Llyiahf/vczjk/fo0;

    move-object v1, p0

    move-object v2, p1

    move-object v5, p2

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/ai4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/ua7;Ljava/lang/Object;)V

    return-void
.end method


# virtual methods
.method public final OooOO0O()Llyiahf/vczjk/so0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ai4;->OooOo0()Llyiahf/vczjk/xh4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/xh4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object v0

    return-object v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/yf4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ai4;->OooOOOO:Llyiahf/vczjk/yf4;

    return-object v0
.end method

.method public final bridge synthetic OooOOO()Llyiahf/vczjk/eo0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ai4;->OooOo00()Llyiahf/vczjk/sa7;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOO0()Llyiahf/vczjk/so0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ai4;->OooOo0()Llyiahf/vczjk/xh4;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOOo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOo0()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/fo0;->OooOOO0:Llyiahf/vczjk/fo0;

    iget-object v1, p0, Llyiahf/vczjk/ai4;->OooOOo:Ljava/lang/Object;

    if-eq v1, v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOoo()Ljava/lang/reflect/Member;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/ai4;->OooOo00()Llyiahf/vczjk/sa7;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/sa7;->Oooo0o()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/iz7;->OooO00o:Llyiahf/vczjk/hy0;

    invoke-virtual {p0}, Llyiahf/vczjk/ai4;->OooOo00()Llyiahf/vczjk/sa7;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/iz7;->OooO0O0(Llyiahf/vczjk/sa7;)Llyiahf/vczjk/t51;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/he4;

    if-eqz v1, :cond_3

    check-cast v0, Llyiahf/vczjk/he4;

    iget-object v1, v0, Llyiahf/vczjk/he4;->OooOOOO:Llyiahf/vczjk/oe4;

    invoke-virtual {v1}, Llyiahf/vczjk/oe4;->OooOOOo()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/oe4;->OooOO0O()Llyiahf/vczjk/me4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/me4;->OooOO0O()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/me4;->OooOO0()Z

    move-result v2

    if-nez v2, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/me4;->OooO()I

    move-result v2

    iget-object v0, v0, Llyiahf/vczjk/he4;->OooOOOo:Llyiahf/vczjk/rt5;

    invoke-interface {v0, v2}, Llyiahf/vczjk/rt5;->Oooo(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Llyiahf/vczjk/me4;->OooO0oo()I

    move-result v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/rt5;->Oooo(I)Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ai4;->OooOOOO:Llyiahf/vczjk/yf4;

    invoke-virtual {v1, v2, v0}, Llyiahf/vczjk/yf4;->OooO0oO(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/reflect/Method;

    move-result-object v0

    return-object v0

    :cond_2
    :goto_0
    const/4 v0, 0x0

    return-object v0

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/ai4;->OooOOoo:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Field;

    return-object v0
.end method

.method public abstract OooOo0()Llyiahf/vczjk/xh4;
.end method

.method public final OooOo00()Llyiahf/vczjk/sa7;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ai4;->OooOo00:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "invoke(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/sa7;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    invoke-static {p1}, Llyiahf/vczjk/mba;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/ai4;

    move-result-object p1

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return v0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ai4;->OooOOOO:Llyiahf/vczjk/yf4;

    iget-object v2, p1, Llyiahf/vczjk/ai4;->OooOOOO:Llyiahf/vczjk/yf4;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ai4;->OooOOOo:Ljava/lang/String;

    iget-object v2, p1, Llyiahf/vczjk/ai4;->OooOOOo:Ljava/lang/String;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ai4;->OooOOo0:Ljava/lang/String;

    iget-object v2, p1, Llyiahf/vczjk/ai4;->OooOOo0:Ljava/lang/String;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ai4;->OooOOo:Ljava/lang/Object;

    iget-object p1, p1, Llyiahf/vczjk/ai4;->OooOOo:Ljava/lang/Object;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    return v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ai4;->OooOOOo:Ljava/lang/String;

    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ai4;->OooOOOO:Llyiahf/vczjk/yf4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget-object v2, p0, Llyiahf/vczjk/ai4;->OooOOOo:Ljava/lang/String;

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/q99;->OooO00o(IILjava/lang/String;)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/ai4;->OooOOo0:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    sget-object v0, Llyiahf/vczjk/en7;->OooO00o:Llyiahf/vczjk/h72;

    invoke-virtual {p0}, Llyiahf/vczjk/ai4;->OooOo00()Llyiahf/vczjk/sa7;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/en7;->OooO0OO(Llyiahf/vczjk/sa7;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
