.class public abstract Llyiahf/vczjk/a64;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/qt5;

.field public static final OooO0O0:Llyiahf/vczjk/qt5;

.field public static final OooO0OO:Llyiahf/vczjk/qt5;

.field public static final OooO0Oo:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    const-string v0, "message"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/a64;->OooO00o:Llyiahf/vczjk/qt5;

    const-string v0, "allowedTargets"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/a64;->OooO0O0:Llyiahf/vczjk/qt5;

    const-string v0, "value"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/a64;->OooO0OO:Llyiahf/vczjk/qt5;

    sget-object v0, Llyiahf/vczjk/w09;->OooOo00:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/dd4;->OooO0OO:Llyiahf/vczjk/hc3;

    new-instance v2, Llyiahf/vczjk/xn6;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOo0o:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/dd4;->OooO0Oo:Llyiahf/vczjk/hc3;

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOo:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/dd4;->OooO0o:Llyiahf/vczjk/hc3;

    new-instance v4, Llyiahf/vczjk/xn6;

    invoke-direct {v4, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    filled-new-array {v2, v3, v4}, [Llyiahf/vczjk/xn6;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/lc5;->o0ooOO0([Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/a64;->OooO0Oo:Ljava/lang/Object;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/b64;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/f07;
    .locals 2

    const-string v0, "kotlinName"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "annotationOwner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "c"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOOO0:Llyiahf/vczjk/hc3;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc3;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/dd4;->OooO0o0:Llyiahf/vczjk/hc3;

    const-string v1, "DEPRECATED_ANNOTATION"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/b64;->OooO00o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/sl7;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p0, Llyiahf/vczjk/i64;

    invoke-direct {p0, v0, p2}, Llyiahf/vczjk/i64;-><init>(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;)V

    return-object p0

    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/a64;->OooO0Oo:Ljava/lang/Object;

    invoke-interface {v0, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/hc3;

    if-eqz p0, :cond_2

    invoke-interface {p1, p0}, Llyiahf/vczjk/b64;->OooO00o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/sl7;

    move-result-object p0

    if-eqz p0, :cond_2

    const/4 p1, 0x0

    invoke-static {p0, p2, p1}, Llyiahf/vczjk/a64;->OooO0O0(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;Z)Llyiahf/vczjk/f07;

    move-result-object p0

    return-object p0

    :cond_2
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooO0O0(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;Z)Llyiahf/vczjk/f07;
    .locals 3

    const-string v0, "annotation"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "c"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/sl7;->OooO00o:Ljava/lang/annotation/Annotation;

    invoke-static {v0}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/dd4;->OooO0OO:Llyiahf/vczjk/hc3;

    const-string v2, "TARGET_ANNOTATION"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hy0;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance p2, Llyiahf/vczjk/u64;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/u64;-><init>(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;)V

    return-object p2

    :cond_0
    sget-object v1, Llyiahf/vczjk/dd4;->OooO0Oo:Llyiahf/vczjk/hc3;

    const-string v2, "RETENTION_ANNOTATION"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hy0;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    new-instance p2, Llyiahf/vczjk/t64;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/t64;-><init>(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;)V

    return-object p2

    :cond_1
    sget-object v1, Llyiahf/vczjk/dd4;->OooO0o:Llyiahf/vczjk/hc3;

    const-string v2, "DOCUMENTED_ANNOTATION"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hy0;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    new-instance p2, Llyiahf/vczjk/z54;

    sget-object v0, Llyiahf/vczjk/w09;->OooOo:Llyiahf/vczjk/hc3;

    invoke-direct {p2, p1, p0, v0}, Llyiahf/vczjk/z54;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/sl7;Llyiahf/vczjk/hc3;)V

    return-object p2

    :cond_2
    sget-object v1, Llyiahf/vczjk/dd4;->OooO0o0:Llyiahf/vczjk/hc3;

    const-string v2, "DEPRECATED_ANNOTATION"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hy0;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    const/4 p0, 0x0

    return-object p0

    :cond_3
    new-instance v0, Llyiahf/vczjk/kr4;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/kr4;-><init>(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;Z)V

    return-object v0
.end method
