.class public final Llyiahf/vczjk/k73;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $measurePolicy:Llyiahf/vczjk/o73;

.field final synthetic this$0:Llyiahf/vczjk/m73;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/m73;Llyiahf/vczjk/s73;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/k73;->this$0:Llyiahf/vczjk/m73;

    iput-object p2, p0, Llyiahf/vczjk/k73;->$measurePolicy:Llyiahf/vczjk/o73;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/ow6;

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/k73;->$measurePolicy:Llyiahf/vczjk/o73;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/ow6;->Oooooo()I

    move-result v0

    invoke-virtual {p1}, Llyiahf/vczjk/ow6;->OooooOo()I

    move-result p1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    move p1, v0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/k73;->this$0:Llyiahf/vczjk/m73;

    invoke-static {v0, p1}, Llyiahf/vczjk/m14;->OooO00o(II)J

    move-result-wide v2

    new-instance p1, Llyiahf/vczjk/m14;

    invoke-direct {p1, v2, v3}, Llyiahf/vczjk/m14;-><init>(J)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p0, Llyiahf/vczjk/k73;->this$0:Llyiahf/vczjk/m73;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
