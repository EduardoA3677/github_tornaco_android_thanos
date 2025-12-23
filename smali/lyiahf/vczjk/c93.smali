.class public final Llyiahf/vczjk/c93;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $focusProperties:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/d93;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/d93;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/c93;->$focusProperties:Llyiahf/vczjk/hl7;

    iput-object p2, p0, Llyiahf/vczjk/c93;->this$0:Llyiahf/vczjk/d93;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/c93;->$focusProperties:Llyiahf/vczjk/hl7;

    iget-object v1, p0, Llyiahf/vczjk/c93;->this$0:Llyiahf/vczjk/d93;

    invoke-virtual {v1}, Llyiahf/vczjk/d93;->o00000Oo()Llyiahf/vczjk/t83;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
