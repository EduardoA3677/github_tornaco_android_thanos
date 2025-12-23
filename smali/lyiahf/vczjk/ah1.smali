.class public final Llyiahf/vczjk/ah1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $owner:Llyiahf/vczjk/tg6;

.field final synthetic $uriHandler:Llyiahf/vczjk/raa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tg6;Llyiahf/vczjk/raa;Llyiahf/vczjk/ze3;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ah1;->$owner:Llyiahf/vczjk/tg6;

    iput-object p2, p0, Llyiahf/vczjk/ah1;->$uriHandler:Llyiahf/vczjk/raa;

    iput-object p3, p0, Llyiahf/vczjk/ah1;->$content:Llyiahf/vczjk/ze3;

    iput p4, p0, Llyiahf/vczjk/ah1;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object p2, p0, Llyiahf/vczjk/ah1;->$owner:Llyiahf/vczjk/tg6;

    iget-object v0, p0, Llyiahf/vczjk/ah1;->$uriHandler:Llyiahf/vczjk/raa;

    iget-object v1, p0, Llyiahf/vczjk/ah1;->$content:Llyiahf/vczjk/ze3;

    iget v2, p0, Llyiahf/vczjk/ah1;->$$changed:I

    or-int/lit8 v2, v2, 0x1

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v2

    invoke-static {p2, v0, v1, p1, v2}, Llyiahf/vczjk/ch1;->OooO00o(Llyiahf/vczjk/tg6;Llyiahf/vczjk/raa;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
