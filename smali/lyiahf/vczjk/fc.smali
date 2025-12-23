.class public final Llyiahf/vczjk/fc;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/gc;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gc;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fc;->this$0:Llyiahf/vczjk/gc;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p2, Llyiahf/vczjk/re8;

    iget-object v0, p0, Llyiahf/vczjk/fc;->this$0:Llyiahf/vczjk/gc;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/gc;->OooOO0(ILlyiahf/vczjk/re8;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
