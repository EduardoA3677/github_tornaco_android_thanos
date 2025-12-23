.class public abstract Llyiahf/vczjk/ho;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/qt5;

.field public static final OooO0O0:Llyiahf/vczjk/qt5;

.field public static final OooO0OO:Llyiahf/vczjk/qt5;

.field public static final OooO0Oo:Llyiahf/vczjk/qt5;

.field public static final OooO0o0:Llyiahf/vczjk/qt5;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "message"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ho;->OooO00o:Llyiahf/vczjk/qt5;

    const-string v0, "replaceWith"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ho;->OooO0O0:Llyiahf/vczjk/qt5;

    const-string v0, "level"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ho;->OooO0OO:Llyiahf/vczjk/qt5;

    const-string v0, "expression"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ho;->OooO0Oo:Llyiahf/vczjk/qt5;

    const-string v0, "imports"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ho;->OooO0o0:Llyiahf/vczjk/qt5;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/hk4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/wj0;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "message"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "replaceWith"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/wj0;

    sget-object v1, Llyiahf/vczjk/w09;->OooOOOO:Llyiahf/vczjk/hc3;

    new-instance v2, Llyiahf/vczjk/y69;

    invoke-direct {v2, p2}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    new-instance p2, Llyiahf/vczjk/xn6;

    sget-object v3, Llyiahf/vczjk/ho;->OooO0Oo:Llyiahf/vczjk/qt5;

    invoke-direct {p2, v3, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/ry;

    sget-object v3, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    new-instance v4, Llyiahf/vczjk/go;

    const/4 v5, 0x0

    invoke-direct {v4, p0, v5}, Llyiahf/vczjk/go;-><init>(Llyiahf/vczjk/hk4;I)V

    invoke-direct {v2, v3, v4}, Llyiahf/vczjk/ry;-><init>(Ljava/util/List;Llyiahf/vczjk/oe3;)V

    new-instance v3, Llyiahf/vczjk/xn6;

    sget-object v4, Llyiahf/vczjk/ho;->OooO0o0:Llyiahf/vczjk/qt5;

    invoke-direct {v3, v4, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    filled-new-array {p2, v3}, [Llyiahf/vczjk/xn6;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/lc5;->o0ooOO0([Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object p2

    invoke-direct {v0, p0, v1, p2}, Llyiahf/vczjk/wj0;-><init>(Llyiahf/vczjk/hk4;Llyiahf/vczjk/hc3;Ljava/util/Map;)V

    new-instance p2, Llyiahf/vczjk/wj0;

    sget-object v1, Llyiahf/vczjk/w09;->OooOOO0:Llyiahf/vczjk/hc3;

    new-instance v2, Llyiahf/vczjk/y69;

    invoke-direct {v2, p1}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/xn6;

    sget-object v3, Llyiahf/vczjk/ho;->OooO00o:Llyiahf/vczjk/qt5;

    invoke-direct {p1, v3, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/io;

    invoke-direct {v2, v0}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/xn6;

    sget-object v3, Llyiahf/vczjk/ho;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-direct {v0, v3, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/zp2;

    sget-object v3, Llyiahf/vczjk/w09;->OooOOO:Llyiahf/vczjk/hc3;

    const-string v4, "topLevelFqName"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Llyiahf/vczjk/hy0;

    invoke-virtual {v3}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v5

    iget-object v3, v3, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v3}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-direct {v4, v5, v3}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-static {p3}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p3

    invoke-direct {v2, v4, p3}, Llyiahf/vczjk/zp2;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/qt5;)V

    new-instance p3, Llyiahf/vczjk/xn6;

    sget-object v3, Llyiahf/vczjk/ho;->OooO0OO:Llyiahf/vczjk/qt5;

    invoke-direct {p3, v3, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    filled-new-array {p1, v0, p3}, [Llyiahf/vczjk/xn6;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/lc5;->o0ooOO0([Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object p1

    invoke-direct {p2, p0, v1, p1}, Llyiahf/vczjk/wj0;-><init>(Llyiahf/vczjk/hk4;Llyiahf/vczjk/hc3;Ljava/util/Map;)V

    return-object p2
.end method
