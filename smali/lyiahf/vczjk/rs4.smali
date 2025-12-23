.class public final Llyiahf/vczjk/rs4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $layer:Llyiahf/vczjk/kj3;

.field final synthetic this$0:Llyiahf/vczjk/bt4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kj3;Llyiahf/vczjk/bt4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rs4;->$layer:Llyiahf/vczjk/kj3;

    iput-object p2, p0, Llyiahf/vczjk/rs4;->this$0:Llyiahf/vczjk/bt4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/gi;

    iget-object v0, p0, Llyiahf/vczjk/rs4;->$layer:Llyiahf/vczjk/kj3;

    invoke-virtual {p1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/kj3;->OooO0o(F)V

    iget-object p1, p0, Llyiahf/vczjk/rs4;->this$0:Llyiahf/vczjk/bt4;

    iget-object p1, p1, Llyiahf/vczjk/bt4;->OooO0OO:Llyiahf/vczjk/et4;

    invoke-virtual {p1}, Llyiahf/vczjk/et4;->OooO00o()Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
