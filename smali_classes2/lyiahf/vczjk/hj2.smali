.class public final synthetic Llyiahf/vczjk/hj2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oj2;

.field public final synthetic OooOOO0:F

.field public final synthetic OooOOOO:Ljava/util/List;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;


# direct methods
.method public synthetic constructor <init>(FLlyiahf/vczjk/oj2;Ljava/util/List;Llyiahf/vczjk/oe3;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/hj2;->OooOOO0:F

    iput-object p2, p0, Llyiahf/vczjk/hj2;->OooOOO:Llyiahf/vczjk/oj2;

    iput-object p3, p0, Llyiahf/vczjk/hj2;->OooOOOO:Ljava/util/List;

    iput-object p4, p0, Llyiahf/vczjk/hj2;->OooOOOo:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0x201

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object v2, p0, Llyiahf/vczjk/hj2;->OooOOOO:Ljava/util/List;

    iget-object v3, p0, Llyiahf/vczjk/hj2;->OooOOOo:Llyiahf/vczjk/oe3;

    iget v0, p0, Llyiahf/vczjk/hj2;->OooOOO0:F

    iget-object v1, p0, Llyiahf/vczjk/hj2;->OooOOO:Llyiahf/vczjk/oj2;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/jp8;->OooO0OO(FLlyiahf/vczjk/oj2;Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
