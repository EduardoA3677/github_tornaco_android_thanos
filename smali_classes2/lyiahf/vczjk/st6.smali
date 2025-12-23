.class public final synthetic Llyiahf/vczjk/st6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/wr0;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:Ljava/util/List;

.field public final synthetic OooOOo:Llyiahf/vczjk/le3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOoo:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/wr0;FLjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/st6;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/st6;->OooOOO:Llyiahf/vczjk/wr0;

    iput p3, p0, Llyiahf/vczjk/st6;->OooOOOO:F

    iput-object p4, p0, Llyiahf/vczjk/st6;->OooOOOo:Ljava/util/List;

    iput-object p5, p0, Llyiahf/vczjk/st6;->OooOOo0:Llyiahf/vczjk/oe3;

    iput-object p6, p0, Llyiahf/vczjk/st6;->OooOOo:Llyiahf/vczjk/le3;

    iput p7, p0, Llyiahf/vczjk/st6;->OooOOoo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/st6;->OooOOoo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object v4, p0, Llyiahf/vczjk/st6;->OooOOo0:Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/st6;->OooOOo:Llyiahf/vczjk/le3;

    iget-object v0, p0, Llyiahf/vczjk/st6;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-object v1, p0, Llyiahf/vczjk/st6;->OooOOO:Llyiahf/vczjk/wr0;

    iget v2, p0, Llyiahf/vczjk/st6;->OooOOOO:F

    iget-object v3, p0, Llyiahf/vczjk/st6;->OooOOOo:Ljava/util/List;

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/vt6;->OooO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/wr0;FLjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
