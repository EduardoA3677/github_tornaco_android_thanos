.class public final synthetic Llyiahf/vczjk/bs9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:F

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:Llyiahf/vczjk/w56;

.field public final synthetic OooOOOo:Llyiahf/vczjk/n62;

.field public final synthetic OooOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo0:Ljava/time/LocalTime;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Ljava/time/LocalTime;Llyiahf/vczjk/oe3;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bs9;->OooOOO0:Llyiahf/vczjk/kl5;

    iput p2, p0, Llyiahf/vczjk/bs9;->OooOOO:F

    iput-object p3, p0, Llyiahf/vczjk/bs9;->OooOOOO:Llyiahf/vczjk/w56;

    iput-object p4, p0, Llyiahf/vczjk/bs9;->OooOOOo:Llyiahf/vczjk/n62;

    iput-object p5, p0, Llyiahf/vczjk/bs9;->OooOOo0:Ljava/time/LocalTime;

    iput-object p6, p0, Llyiahf/vczjk/bs9;->OooOOo:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    iget-object v4, p0, Llyiahf/vczjk/bs9;->OooOOo0:Ljava/time/LocalTime;

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0x187

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object v3, p0, Llyiahf/vczjk/bs9;->OooOOOo:Llyiahf/vczjk/n62;

    iget-object v5, p0, Llyiahf/vczjk/bs9;->OooOOo:Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/bs9;->OooOOO0:Llyiahf/vczjk/kl5;

    iget v1, p0, Llyiahf/vczjk/bs9;->OooOOO:F

    iget-object v2, p0, Llyiahf/vczjk/bs9;->OooOOOO:Llyiahf/vczjk/w56;

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/fu6;->OooO0o(Llyiahf/vczjk/kl5;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Ljava/time/LocalTime;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
