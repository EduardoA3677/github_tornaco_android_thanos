.class public final synthetic Llyiahf/vczjk/xk0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Ljava/lang/String;

.field public final synthetic OooOOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOo:Llyiahf/vczjk/qv3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/qv3;

.field public final synthetic OooOOoo:Z

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/qv3;Llyiahf/vczjk/qv3;ZII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xk0;->OooOOO0:Ljava/lang/String;

    iput-boolean p2, p0, Llyiahf/vczjk/xk0;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/xk0;->OooOOOO:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/xk0;->OooOOOo:Llyiahf/vczjk/hl5;

    iput-object p5, p0, Llyiahf/vczjk/xk0;->OooOOo0:Llyiahf/vczjk/qv3;

    iput-object p6, p0, Llyiahf/vczjk/xk0;->OooOOo:Llyiahf/vczjk/qv3;

    iput-boolean p7, p0, Llyiahf/vczjk/xk0;->OooOOoo:Z

    iput p8, p0, Llyiahf/vczjk/xk0;->OooOo00:I

    iput p9, p0, Llyiahf/vczjk/xk0;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/xk0;->OooOo00:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget-boolean v6, p0, Llyiahf/vczjk/xk0;->OooOOoo:Z

    iget v9, p0, Llyiahf/vczjk/xk0;->OooOo0:I

    iget-object v0, p0, Llyiahf/vczjk/xk0;->OooOOO0:Ljava/lang/String;

    iget-boolean v1, p0, Llyiahf/vczjk/xk0;->OooOOO:Z

    iget-object v2, p0, Llyiahf/vczjk/xk0;->OooOOOO:Llyiahf/vczjk/le3;

    iget-object v3, p0, Llyiahf/vczjk/xk0;->OooOOOo:Llyiahf/vczjk/hl5;

    iget-object v4, p0, Llyiahf/vczjk/xk0;->OooOOo0:Llyiahf/vczjk/qv3;

    iget-object v5, p0, Llyiahf/vczjk/xk0;->OooOOo:Llyiahf/vczjk/qv3;

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/zsa;->OooO0o0(Ljava/lang/String;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/qv3;Llyiahf/vczjk/qv3;ZLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
