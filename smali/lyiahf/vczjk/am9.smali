.class public final Llyiahf/vczjk/am9;
.super Llyiahf/vczjk/n62;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOo:Llyiahf/vczjk/n62;

.field public final synthetic OooOOo0:Llyiahf/vczjk/y85;

.field public final synthetic OooOOoo:Llyiahf/vczjk/gd2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/y85;Llyiahf/vczjk/n62;Llyiahf/vczjk/gd2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/am9;->OooOOo0:Llyiahf/vczjk/y85;

    iput-object p2, p0, Llyiahf/vczjk/am9;->OooOOo:Llyiahf/vczjk/n62;

    iput-object p3, p0, Llyiahf/vczjk/am9;->OooOOoo:Llyiahf/vczjk/gd2;

    const/16 p1, 0x15

    invoke-direct {p0, p1}, Llyiahf/vczjk/n62;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final o000OOo(Llyiahf/vczjk/y85;)Ljava/lang/Object;
    .locals 13

    iget v0, p1, Llyiahf/vczjk/y85;->OooO00o:F

    iget v1, p1, Llyiahf/vczjk/y85;->OooO0O0:F

    iget-object v2, p1, Llyiahf/vczjk/y85;->OooO0OO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/gd2;

    iget-object v2, v2, Llyiahf/vczjk/gd2;->OooO00o:Ljava/lang/String;

    iget-object v3, p1, Llyiahf/vczjk/y85;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/gd2;

    iget-object v3, v3, Llyiahf/vczjk/gd2;->OooO00o:Ljava/lang/String;

    iget v4, p1, Llyiahf/vczjk/y85;->OooO0o0:F

    iget v5, p1, Llyiahf/vczjk/y85;->OooO0o:F

    iget v6, p1, Llyiahf/vczjk/y85;->OooO0oO:F

    iget-object v7, p0, Llyiahf/vczjk/am9;->OooOOo0:Llyiahf/vczjk/y85;

    iput v0, v7, Llyiahf/vczjk/y85;->OooO00o:F

    iput v1, v7, Llyiahf/vczjk/y85;->OooO0O0:F

    iput-object v2, v7, Llyiahf/vczjk/y85;->OooO0OO:Ljava/lang/Object;

    iput-object v3, v7, Llyiahf/vczjk/y85;->OooO0Oo:Ljava/lang/Object;

    iput v4, v7, Llyiahf/vczjk/y85;->OooO0o0:F

    iput v5, v7, Llyiahf/vczjk/y85;->OooO0o:F

    iput v6, v7, Llyiahf/vczjk/y85;->OooO0oO:F

    iget-object v0, p0, Llyiahf/vczjk/am9;->OooOOo:Llyiahf/vczjk/n62;

    iget-object v0, v0, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/go8;

    check-cast v0, Ljava/lang/String;

    iget v1, p1, Llyiahf/vczjk/y85;->OooO0o:F

    const/high16 v2, 0x3f800000    # 1.0f

    cmpl-float v1, v1, v2

    if-nez v1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/y85;->OooO0Oo:Ljava/lang/Object;

    :goto_0
    check-cast p1, Llyiahf/vczjk/gd2;

    goto :goto_1

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/y85;->OooO0OO:Ljava/lang/Object;

    goto :goto_0

    :goto_1
    iget-object v1, p1, Llyiahf/vczjk/gd2;->OooO0O0:Ljava/lang/String;

    iget v2, p1, Llyiahf/vczjk/gd2;->OooO0OO:F

    iget v3, p1, Llyiahf/vczjk/gd2;->OooO0Oo:I

    iget v4, p1, Llyiahf/vczjk/gd2;->OooO0o0:I

    iget v5, p1, Llyiahf/vczjk/gd2;->OooO0o:F

    iget v6, p1, Llyiahf/vczjk/gd2;->OooO0oO:F

    iget v7, p1, Llyiahf/vczjk/gd2;->OooO0oo:I

    iget v8, p1, Llyiahf/vczjk/gd2;->OooO:I

    iget v9, p1, Llyiahf/vczjk/gd2;->OooOO0:F

    iget-boolean v10, p1, Llyiahf/vczjk/gd2;->OooOO0O:Z

    iget-object v11, p1, Llyiahf/vczjk/gd2;->OooOO0o:Landroid/graphics/PointF;

    iget-object p1, p1, Llyiahf/vczjk/gd2;->OooOOO0:Landroid/graphics/PointF;

    iget-object v12, p0, Llyiahf/vczjk/am9;->OooOOoo:Llyiahf/vczjk/gd2;

    iput-object v0, v12, Llyiahf/vczjk/gd2;->OooO00o:Ljava/lang/String;

    iput-object v1, v12, Llyiahf/vczjk/gd2;->OooO0O0:Ljava/lang/String;

    iput v2, v12, Llyiahf/vczjk/gd2;->OooO0OO:F

    iput v3, v12, Llyiahf/vczjk/gd2;->OooO0Oo:I

    iput v4, v12, Llyiahf/vczjk/gd2;->OooO0o0:I

    iput v5, v12, Llyiahf/vczjk/gd2;->OooO0o:F

    iput v6, v12, Llyiahf/vczjk/gd2;->OooO0oO:F

    iput v7, v12, Llyiahf/vczjk/gd2;->OooO0oo:I

    iput v8, v12, Llyiahf/vczjk/gd2;->OooO:I

    iput v9, v12, Llyiahf/vczjk/gd2;->OooOO0:F

    iput-boolean v10, v12, Llyiahf/vczjk/gd2;->OooOO0O:Z

    iput-object v11, v12, Llyiahf/vczjk/gd2;->OooOO0o:Landroid/graphics/PointF;

    iput-object p1, v12, Llyiahf/vczjk/gd2;->OooOOO0:Landroid/graphics/PointF;

    return-object v12
.end method
