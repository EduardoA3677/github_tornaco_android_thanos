.class public final synthetic Llyiahf/vczjk/qx4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/di6;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:Llyiahf/vczjk/tv7;

.field public final synthetic OooOOo0:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;Ljava/util/List;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qx4;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/qx4;->OooOOO:Llyiahf/vczjk/di6;

    iput p3, p0, Llyiahf/vczjk/qx4;->OooOOOO:F

    iput-object p4, p0, Llyiahf/vczjk/qx4;->OooOOOo:Llyiahf/vczjk/tv7;

    iput-object p5, p0, Llyiahf/vczjk/qx4;->OooOOo0:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0x187

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object v3, p0, Llyiahf/vczjk/qx4;->OooOOOo:Llyiahf/vczjk/tv7;

    iget-object v4, p0, Llyiahf/vczjk/qx4;->OooOOo0:Ljava/util/List;

    iget-object v0, p0, Llyiahf/vczjk/qx4;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-object v1, p0, Llyiahf/vczjk/qx4;->OooOOO:Llyiahf/vczjk/di6;

    iget v2, p0, Llyiahf/vczjk/qx4;->OooOOOO:F

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/r02;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;Ljava/util/List;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
