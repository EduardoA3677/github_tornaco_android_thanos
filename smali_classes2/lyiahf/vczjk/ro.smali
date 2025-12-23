.class public abstract Llyiahf/vczjk/ro;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:[Llyiahf/vczjk/th4;

.field public static final OooO0O0:Llyiahf/vczjk/o55;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/ro;

    const-string v2, "annotationsAttribute"

    const-string v3, "getAnnotationsAttribute(Lorg/jetbrains/kotlin/types/TypeAttributes;)Lorg/jetbrains/kotlin/types/AnnotationsTypeAttribute;"

    const/4 v4, 0x1

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    new-array v2, v4, [Llyiahf/vczjk/th4;

    const/4 v3, 0x0

    aput-object v0, v2, v3

    sput-object v2, Llyiahf/vczjk/ro;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    const-class v2, Llyiahf/vczjk/qo;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/o55;

    invoke-interface {v1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/xo8;->OooO(Ljava/lang/String;)I

    move-result v0

    invoke-direct {v2, v0}, Llyiahf/vczjk/o55;-><init>(I)V

    sput-object v2, Llyiahf/vczjk/ro;->OooO0O0:Llyiahf/vczjk/o55;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/ko;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/ro;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    sget-object v1, Llyiahf/vczjk/ro;->OooO0O0:Llyiahf/vczjk/o55;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "property"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p0, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    iget v0, v1, Llyiahf/vczjk/o55;->OooOOO0:I

    invoke-virtual {p0, v0}, Llyiahf/vczjk/gy;->get(I)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/qo;

    if-eqz p0, :cond_1

    iget-object p0, p0, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    if-nez p0, :cond_0

    goto :goto_0

    :cond_0
    return-object p0

    :cond_1
    :goto_0
    sget-object p0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    return-object p0
.end method
