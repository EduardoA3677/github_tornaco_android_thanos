.class public final Llyiahf/vczjk/ec;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $oldNode:Llyiahf/vczjk/se8;

.field final synthetic this$0:Llyiahf/vczjk/gc;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/se8;Llyiahf/vczjk/gc;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ec;->$oldNode:Llyiahf/vczjk/se8;

    iput-object p2, p0, Llyiahf/vczjk/ec;->this$0:Llyiahf/vczjk/gc;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p2, Llyiahf/vczjk/re8;

    iget-object v0, p0, Llyiahf/vczjk/ec;->$oldNode:Llyiahf/vczjk/se8;

    iget-object v0, v0, Llyiahf/vczjk/se8;->OooO0O0:Llyiahf/vczjk/pr5;

    iget v1, p2, Llyiahf/vczjk/re8;->OooO0oO:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pr5;->OooO0O0(I)Z

    move-result v0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ec;->this$0:Llyiahf/vczjk/gc;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/gc;->OooOO0(ILlyiahf/vczjk/re8;)V

    iget-object p1, p0, Llyiahf/vczjk/ec;->this$0:Llyiahf/vczjk/gc;

    iget-object p1, p1, Llyiahf/vczjk/gc;->OooOo00:Llyiahf/vczjk/jj0;

    invoke-interface {p1, v1}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-object v1
.end method
