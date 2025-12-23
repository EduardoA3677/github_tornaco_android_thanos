.class public final synthetic Llyiahf/vczjk/rr8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOO0:F

.field public final synthetic OooOOOO:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOOo:Z

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:Llyiahf/vczjk/m01;

.field public final synthetic OooOOoo:Llyiahf/vczjk/ir8;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:Llyiahf/vczjk/rr5;

.field public final synthetic OooOo0O:I


# direct methods
.method public synthetic constructor <init>(FLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/m01;ILlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/rr8;->OooOOO0:F

    iput-object p2, p0, Llyiahf/vczjk/rr8;->OooOOO:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/rr8;->OooOOOO:Llyiahf/vczjk/hl5;

    iput-boolean p4, p0, Llyiahf/vczjk/rr8;->OooOOOo:Z

    iput-object p5, p0, Llyiahf/vczjk/rr8;->OooOOo0:Llyiahf/vczjk/m01;

    iput p6, p0, Llyiahf/vczjk/rr8;->OooOOo:I

    iput-object p7, p0, Llyiahf/vczjk/rr8;->OooOOoo:Llyiahf/vczjk/ir8;

    iput-object p8, p0, Llyiahf/vczjk/rr8;->OooOo00:Llyiahf/vczjk/rr5;

    iput p9, p0, Llyiahf/vczjk/rr8;->OooOo0:I

    iput p10, p0, Llyiahf/vczjk/rr8;->OooOo0O:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/rr8;->OooOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget-object v7, p0, Llyiahf/vczjk/rr8;->OooOo00:Llyiahf/vczjk/rr5;

    iget v10, p0, Llyiahf/vczjk/rr8;->OooOo0O:I

    iget v0, p0, Llyiahf/vczjk/rr8;->OooOOO0:F

    iget-object v1, p0, Llyiahf/vczjk/rr8;->OooOOO:Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/rr8;->OooOOOO:Llyiahf/vczjk/hl5;

    iget-boolean v3, p0, Llyiahf/vczjk/rr8;->OooOOOo:Z

    iget-object v4, p0, Llyiahf/vczjk/rr8;->OooOOo0:Llyiahf/vczjk/m01;

    iget v5, p0, Llyiahf/vczjk/rr8;->OooOOo:I

    iget-object v6, p0, Llyiahf/vczjk/rr8;->OooOOoo:Llyiahf/vczjk/ir8;

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/as8;->OooO00o(FLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/m01;ILlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
