.class public final synthetic Llyiahf/vczjk/yla;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/util/List;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:Ljava/lang/Integer;

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:Llyiahf/vczjk/n62;

.field public final synthetic OooOOo0:Llyiahf/vczjk/w56;

.field public final synthetic OooOOoo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:Llyiahf/vczjk/oe3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;Ljava/util/List;Ljava/lang/Integer;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yla;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/yla;->OooOOO:Ljava/util/List;

    iput-object p3, p0, Llyiahf/vczjk/yla;->OooOOOO:Ljava/lang/Integer;

    iput p4, p0, Llyiahf/vczjk/yla;->OooOOOo:F

    iput-object p5, p0, Llyiahf/vczjk/yla;->OooOOo0:Llyiahf/vczjk/w56;

    iput-object p6, p0, Llyiahf/vczjk/yla;->OooOOo:Llyiahf/vczjk/n62;

    iput-object p7, p0, Llyiahf/vczjk/yla;->OooOOoo:Llyiahf/vczjk/oe3;

    iput-object p8, p0, Llyiahf/vczjk/yla;->OooOo00:Llyiahf/vczjk/oe3;

    iput p9, p0, Llyiahf/vczjk/yla;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/yla;->OooOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget-object v1, p0, Llyiahf/vczjk/yla;->OooOOO:Ljava/util/List;

    iget-object v5, p0, Llyiahf/vczjk/yla;->OooOOo:Llyiahf/vczjk/n62;

    iget-object v6, p0, Llyiahf/vczjk/yla;->OooOOoo:Llyiahf/vczjk/oe3;

    iget-object v7, p0, Llyiahf/vczjk/yla;->OooOo00:Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/yla;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-object v2, p0, Llyiahf/vczjk/yla;->OooOOOO:Ljava/lang/Integer;

    iget v3, p0, Llyiahf/vczjk/yla;->OooOOOo:F

    iget-object v4, p0, Llyiahf/vczjk/yla;->OooOOo0:Llyiahf/vczjk/w56;

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/cl6;->OooO0Oo(Llyiahf/vczjk/kl5;Ljava/util/List;Ljava/lang/Integer;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
